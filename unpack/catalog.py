import hashlib
import json
import os
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

import pefile
from .binary import read_u32


def digest(data):
    return hashlib.sha256(data).hexdigest()


def extract_module(data):
    with pefile.PE(data=data, fast_load=True) as pe:
        if pe.FILE_HEADER.Machine != 0x8664 or pe.OPTIONAL_HEADER.Magic != 0x20B:
            raise ValueError("not an AMD64 PE32+ DLL")
        pe.parse_data_directories(directories=[0])
        exports = []
        for item in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []):
            name = item.name.decode("ascii") if item.name else None
            forwarder = item.forwarder.decode("ascii") if item.forwarder else None
            record = {"name": name, "ordinal": item.ordinal, "rva": item.address,
                      "forwarder": forwarder}
            if name and name.startswith(("Nt", "Zw")) and not forwarder:
                code = pe.get_data(item.address, 32)

                if code[:4] == b"\x4c\x8b\xd1\xb8" and b"\x0f\x05" in code[8:]:
                    record["syscall"] = read_u32(code, 4)
            exports.append(record)
        return {"sha256": digest(data), "size": len(data), "machine": "AMD64",
                "timestamp": pe.FILE_HEADER.TimeDateStamp, "exports": exports}


def parse_api_set(data):

    if len(data) < 28:
        raise ValueError("truncated API-set namespace")
    version, size, _, count, entries, _, _ = struct.unpack_from("<7I", data)
    if version != 6 or not 28 <= size <= len(data):
        raise ValueError("unsupported or truncated API-set namespace")

    def checked(offset, length):
        if offset < 0 or length < 0 or offset + length > size:
            raise ValueError("API-set field outside namespace")
        return data[offset:offset + length]

    def string(offset, length):
        if length % 2:
            raise ValueError("invalid API-set string length")
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
            raise ValueError(f"ambiguous API-set default: {contract}")
        if defaults:
            result[contract] = defaults.pop()
    return result


def capture(output):
    if sys.platform != "win32" or struct.calcsize("P") != 8:
        raise ValueError("capture requires 64-bit Python on Windows; consumption does not")
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
        def value(name):
            return winreg.QueryValueEx(key, name)[0]
        version = {"major": value("CurrentMajorVersionNumber"),
                   "minor": value("CurrentMinorVersionNumber"),
                   "build": int(value("CurrentBuildNumber")), "ubr": value("UBR"),
                   "platform_id": 2, "service_pack_major": 0, "service_pack_minor": 0,
                   "product_type": sys.getwindowsversion().product_type,
                   "suite_mask": sys.getwindowsversion().suite_mask}
    system32 = Path(os.environ["SystemRoot"]) / "System32"
    modules, skipped = {}, []
    ntdll = None
    api_sets = {}
    for path in sorted(system32.glob("*.dll"), key=lambda p: p.name.lower()):
        try:
            data = path.read_bytes()
            modules[path.name.lower()] = extract_module(data)
            if path.name.lower() == "ntdll.dll":
                ntdll = data
            elif path.name.lower() == "apisetschema.dll":
                with pefile.PE(data=data, fast_load=True) as schema:
                    section = next(s for s in schema.sections if s.Name.rstrip(b"\0") == b".apiset")
                    api_sets = parse_api_set(section.get_data())
        except (OSError, ValueError, pefile.PEFormatError, UnicodeError) as exc:
            skipped.append({"module": path.name, "reason": str(exc)})
    if ntdll is None:
        raise ValueError("could not capture AMD64 ntdll.dll")


    with pefile.PE(data=ntdll) as pe:
        fixed = pe.VS_FIXEDFILEINFO[0]
        file_version = [fixed.FileVersionMS >> 16, fixed.FileVersionMS & 0xffff,
                        fixed.FileVersionLS >> 16, fixed.FileVersionLS & 0xffff]
    version["ntdll_file_version"] = file_version
    document = {"schema": 1, "created_utc": datetime.now(timezone.utc).isoformat(),
                "windows": version, "modules": modules, "skipped": skipped, "api_sets": api_sets,
                "clean_ntdll": {"file": "ntdll.dll", "sha256": digest(ntdll)}}
    output.mkdir(parents=True, exist_ok=False)
    (output / "ntdll.dll").write_bytes(ntdll)
    (output / "catalog.json").write_text(json.dumps(document, indent=2), encoding="utf-8")
    return document


def find_or_capture_catalog(roots):
    for root in roots:
        directory = root / "catalog"
        if (directory / "catalog.json").is_file():
            return directory
    directory = roots[-1] / "catalog"
    if directory.exists():
        raise ValueError(f"Incomplete catalog: {directory}")
    print("Catalog: build")
    capture(directory)
    return directory


class Catalog:
    def __init__(self, directory):
        self.directory = Path(directory)
        raw = (self.directory / "catalog.json").read_bytes()
        self.sha256 = digest(raw)
        self.document = json.loads(raw)
        if self.document.get("schema") != 1:
            raise ValueError("unsupported catalog schema")
        self.windows = self.document["windows"]
        for field in ("major", "minor", "build"):
            if type(self.windows[field]) is not int or not 0 <= self.windows[field] <= 65535:
                raise ValueError(f"invalid Windows {field}")
        self.modules = self.document["modules"]
        raw_ntdll = (self.directory / "ntdll.dll").read_bytes()
        expected = self.document["clean_ntdll"]["sha256"]
        if digest(raw_ntdll) != expected or self.modules["ntdll.dll"]["sha256"] != expected:
            raise ValueError("clean ntdll hash does not match catalog")

        self.ntdll_bytes = raw_ntdll

    def exports(self, name):
        name = name.lower()
        visited = set()
        while name not in self.modules and name in self.document.get("api_sets", {}):
            if name in visited:
                raise ValueError("cyclic API-set mapping")
            visited.add(name)
            name = self.document["api_sets"][name]
        if name not in self.modules:
            raise ValueError(f"module not captured in catalog: {name}")
        return self.modules[name]["exports"]

    def syscall_catalog(self):
        result = {}
        for record in self.exports("ntdll.dll"):
            if "syscall" in record:
                result.setdefault(record["syscall"], []).append(record["name"])
        return {key: sorted(set(names)) for key, names in result.items()}
