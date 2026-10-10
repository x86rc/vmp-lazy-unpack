import json
import os
import struct
import sys
from pathlib import Path

import pefile
from .arch import MODE32, MODE64
from .binary import read_u32


def catalog_json_name(arch=MODE64):
    return "catalog_32.json" if arch.bits == 32 else "catalog.json"


def ntdll_name(arch=MODE64):
    return "ntdll_32.dll" if arch.bits == 32 else "ntdll.dll"


def stub_syscall_number(code, arch=MODE64):
    if arch.bits == 64:
        if code[:4] == b"\x4c\x8b\xd1\xb8" and b"\x0f\x05" in code[8:]:
            return read_u32(code, 4)
        return None
    if code[:1] != b"\xb8":
        return None
    if code[5:6] == b"\xba" and code[10:12] in (b"\xff\xd2", b"\xff\x12"):
        return read_u32(code, 1)
    from capstone import Cs, CS_ARCH_X86
    for instruction in Cs(CS_ARCH_X86, arch.cs_mode).disasm(code, 0):
        if instruction.mnemonic.startswith('ret'):
            break
        if instruction.bytes in (b'\xcd\x2e', b'\x0f\x34', b'\x64\xff\x15\xc0\0\0\0'):
            return read_u32(code, 1)
    return None


def extract_module(data, arch=MODE64):
    with pefile.PE(data=data, fast_load=True) as pe:
        if (pe.FILE_HEADER.Machine, pe.OPTIONAL_HEADER.Magic) != (arch.machine, arch.magic):
            raise ValueError(f"expected windows {'32 bit' if arch.bits == 32 else '64 bit'} binary")
        pe.parse_data_directories(directories=[0])
        exports = []
        for item in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []):
            name = item.name.decode("ascii") if item.name else None
            record = {"name": name, "ordinal": item.ordinal}
            if name and name.startswith(("Nt", "Zw")) and not item.forwarder:
                number = stub_syscall_number(pe.get_data(item.address, 32), arch)
                if number is not None:
                    record["syscall"] = number
            exports.append(record)
        return {"exports": exports}


def parse_api_set(data):

    if len(data) < 28:
        raise ValueError("truncated api set namespace")
    version, size, _, count, entries, _, _ = struct.unpack_from("<7I", data)
    if version != 6 or not 28 <= size <= len(data):
        raise ValueError("unsupported or truncated api set namespace")

    def checked(offset, length):
        if offset < 0 or length < 0 or offset + length > size:
            raise ValueError("api set field outside namespace")
        return data[offset:offset + length]

    def string(offset, length):
        if length % 2:
            raise ValueError("invalid api set string length")
        return checked(offset, length).decode("utf-16-le").lower()

    checked(entries, count * 24)
    result = {}
    for index in range(count):
        _, name, length, _, values, value_count = struct.unpack_from("<6I", data, entries + index * 24)
        contract = string(name, length) + ".dll"
        checked(values, value_count * 20)
        defaults = set()
        for value_index in range(value_count):
            _, _, alias_length, host, host_length = struct.unpack_from("<5I", data, values + value_index * 20)
            if alias_length == 0 and host_length:
                defaults.add(string(host, host_length))
        if len(defaults) > 1:
            raise ValueError(f"multiple api set defaults for {contract}")
        if defaults:
            result[contract] = defaults.pop()
    return result


def system_dll_dir(arch=MODE64, system_root=None):
    root = Path(system_root or os.environ["SystemRoot"])
    if arch.bits == 32:
        wow64 = root / "SysWOW64"
        if wow64.is_dir():
            return wow64
    return root / "System32"


def capture(output, arch=MODE64):
    label = "32 bit" if arch.bits == 32 else "64 bit"
    if sys.platform != "win32":
        raise ValueError(f"capture requires windows "
                         f"(copy {catalog_json_name(arch)} and {ntdll_name(arch)} into catalog/)")
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
        def value(name):
            return winreg.QueryValueEx(key, name)[0]
        version = {"major": value("CurrentMajorVersionNumber"),
                   "minor": value("CurrentMinorVersionNumber"),
                   "build": int(value("CurrentBuildNumber")),
                   "platform_id": 2, "service_pack_major": 0, "service_pack_minor": 0,
                   "product_type": sys.getwindowsversion().product_type,
                   "suite_mask": sys.getwindowsversion().suite_mask}
    system_dir = system_dll_dir(arch)
    modules = {}
    ntdll = None
    api_sets = {}
    paths = sorted(system_dir.glob("*.dll"), key=lambda p: p.name.lower())
    for path in paths:
        try:
            data = path.read_bytes()
            module = extract_module(data, arch)
            if path.name.lower() == "ntdll.dll":
                ntdll = data
            elif path.name.lower() == "apisetschema.dll":
                with pefile.PE(data=data, fast_load=True) as schema:
                    section = next(s for s in schema.sections if s.Name.rstrip(b"\0") == b".apiset")
                    api_sets = parse_api_set(section.get_data())
            modules[path.name.lower()] = module
        except (OSError, ValueError, pefile.PEFormatError, UnicodeError):
            continue
    if ntdll is None:
        raise ValueError(f"could not capture {label} ntdll.dll from {system_dir}")
    if not any("syscall" in record for name in ("ntdll.dll",) if name in modules
               for record in modules[name]["exports"]):
        raise ValueError(f"no {label} syscalls recognized in ntdll.dll, refusing to write an empty catalog")
    document = {"schema": 1, "machine": arch.machine, "windows": version,
                "modules": modules, "api_sets": api_sets}
    if arch.bits == 32:
        document["wow64"] = system_dir.name.lower() == "syswow64"
    output.mkdir(parents=True, exist_ok=True)
    (output / ntdll_name(arch)).write_bytes(ntdll)
    (output / catalog_json_name(arch)).write_text(json.dumps(document, indent=2), encoding="utf-8")
    return document


def find_or_capture_catalog(roots, arch=MODE64):
    for root in roots:
        directory = root / "catalog"
        pair = (directory / catalog_json_name(arch), directory / ntdll_name(arch))
        if pair[0].is_file() and pair[1].is_file():
            return directory
        if pair[0].is_file() != pair[1].is_file():
            raise ValueError(f"incomplete catalog {directory}")
    directory = roots[-1] / "catalog"
    capture(directory, arch)
    return directory


def ensure_catalog_arch(catalog, arch):
    machine = getattr(catalog, "machine", arch.machine)
    if machine != arch.machine:
        label = "32 bit" if arch.bits == 32 else "64 bit"
        raise ValueError(f"catalog at {catalog.directory} does not match {label} "
                         f"(pair {'--32bit' if arch.bits == 32 else '64-bit'} binaries "
                         f"with a matching catalog)")


class Catalog:
    def __init__(self, directory, arch=MODE64):
        self.directory = Path(directory)
        self.arch = arch
        raw = (self.directory / catalog_json_name(arch)).read_bytes()
        self.document = json.loads(raw)
        if self.document.get("schema") != 1:
            raise ValueError("unsupported catalog schema")
        self.windows = self.document["windows"]
        for field in ("major", "minor", "build"):
            if type(self.windows[field]) is not int or not 0 <= self.windows[field] <= 65535:
                raise ValueError(f"invalid windows {field}")
        self.modules = self.document["modules"]
        raw_ntdll = (self.directory / ntdll_name(arch)).read_bytes()
        self.ntdll_bytes = raw_ntdll
        if arch.bits == 32 and self.modules.get('ntdll.dll', {}).get('exports'):
            parsed = extract_module(raw_ntdll, arch)
            numbers = {record['ordinal']: record['syscall'] for record in parsed['exports'] if 'syscall' in record}
            for record in self.modules.get('ntdll.dll', {}).get('exports', []):
                if record['ordinal'] in numbers:
                    record['syscall'] = numbers[record['ordinal']]

    @property
    def wow64(self):
        return self.arch.bits == 32 and self.document.get('wow64', any(
            record['name'] == 'Wow64Transition' for record in self.exports('ntdll.dll')))

    @property
    def machine(self):
        declared = self.document.get("machine")
        if declared in (0x14C, 0x8664):
            return declared
        try:
            with pefile.PE(data=self.ntdll_bytes, fast_load=True) as pe:
                return pe.FILE_HEADER.Machine
        except Exception as exc:
            raise ValueError(f"catalog {ntdll_name(self.arch)} at {self.directory} is not a valid PE") from exc

    def exports(self, name):
        name = name.lower()
        visited = set()
        while name not in self.modules and name in self.document.get("api_sets", {}):
            if name in visited:
                raise ValueError("api set mapping cycle")
            visited.add(name)
            name = self.document["api_sets"][name]
        if name not in self.modules:
            raise ValueError(f"module missing from catalog {name}")
        return self.modules[name]["exports"]

    def syscall_catalog(self):
        result = {}
        for record in self.exports("ntdll.dll"):
            if "syscall" in record:
                result.setdefault(record["syscall"], []).append(record["name"])
                if self.wow64:
                    result.setdefault(record["syscall"] & 0xFFFF, []).append(record["name"])
        return {key: sorted(set(names)) for key, names in result.items()}


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(prog="python -m unpack.catalog",
                                     description="capture a windows dll export catalog")
    parser.add_argument("--32bit", dest="arch32", action="store_true")
    parser.add_argument("output", type=Path, nargs="?")
    args = parser.parse_args(argv)
    arch = MODE32 if args.arch32 else MODE64
    output = args.output or (Path.cwd() / "catalog")
    try:
        capture(output, arch)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
