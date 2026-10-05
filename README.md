# vmp-lazy-unpack<br>[![@x86rc](https://img.shields.io/badge/%40x86rc-000000?style=flat&logo=x&logoColor=white)](https://x.com/x86rc)

An emulation-based unpacker and import resolver for Windows x64 VMProtect 3.x binaries.

The project started as a script used to unpack VMProtect 3 in our devirtualization pipeline. It does this without the need to attach a debugger or dump live.

## How

The project uses Unicorn to emulate syscalls used by VMProtect's unpacker and import resolver.

- The project ships with a catalog of Windows dll exports pinned to a specific Windows build.
- The binary is mapped with a simulated Windows process.
- Emulation starts at the entry point, handling api and syscalls while tracking restored code and resolved imports.
- We stop emulation when execution enters restored code.
- The IAT is rebuilt from collected meta, recognized import stubs are patched, exception tables are fixed.
- The unpacked, emulated process is then dumped from memory to disk.

## Installation

```powershell
py -m pip install -e .
```

For decent speeds its recommended to install Microsoft C++ Build Tools so the C helper is used. If not installed the unpacking falls back to purely python based hooks (slower).

## Usage

```powershell
py -m unpack "C:\path\file.exe"
```

## Limitations

- Only supports Windows x64. Tested against VMProtect 3.4, 3.9, and 3.10.
- This will not devirtualize code.
- This will not resolve external calls inside virtualized functions automatically. These recovered imports are included in IAT for later lifting.

---

<p align="center">
  Want to chat about deobfuscation or reverse engineering?<br><br>
  <a href="https://discord.gg/Dvcj2qQVsg">
    <img src="https://img.shields.io/badge/Find%20us%20here%20too-5865F2?style=for-the-badge&amp;logo=discord&amp;logoColor=white" alt="Find us here too">
  </a>
</p>
