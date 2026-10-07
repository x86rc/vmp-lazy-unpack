import json
import time
from collections import Counter, deque

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from unicorn import UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_WRITE, UcError
import unicorn.x86_const as ux

from .records import format_report


class Diagnostics:
    def __init__(self, directory, max_bytes=32 * 1024 * 1024):
        self.directory = directory
        self.max_bytes = max_bytes
        self.bytes_written = 0
        self.limited = False
        self.started = time.monotonic()
        self.mappings = []
        self.hooks = []
        self.block_hits = Counter()
        self.block_sizes = {}
        self.untracked_block_visits = 0
        self.candidates = []
        self.candidate_matches = {}
        self.ntdll_readers = {}
        self.untracked_ntdll_reads = 0

    def __enter__(self):
        self.log = (self.directory / 'diagnostics.jsonl').open('w', encoding='ascii')
        return self

    def __exit__(self, *exc):
        try:
            self.save_ntdll_reads()
            for uc, hook in self.hooks:
                uc.hook_del(hook)
        finally:
            self.log.close()

    def record(self, kind, **data):
        if self.limited:
            return
        row = {"elapsed_seconds": round(time.monotonic() - self.started, 3),
               "kind": kind, **format_report(data)}
        line = json.dumps(row) + '\n'
        if self.bytes_written + len(line) > self.max_bytes:
            line = json.dumps({"kind": "log_limit", "max_bytes": self.max_bytes}) + '\n'
            self.limited = True
        self.log.write(line)
        self.log.flush()
        self.bytes_written += len(line)

    def observe_block(self, address, size):
        if address not in self.block_hits and len(self.block_hits) >= 32768:
            self.untracked_block_visits += 1
            return
        self.block_hits[address] += 1
        self.block_sizes[address] = size

    def register_candidate(self, kind, entry, ranges):
        self.candidates.append({"kind": kind, "entry": hex(entry), "ranges": tuple(ranges),
                                "ntdll_reads": 0, "ntdll_bytes_read": 0})
        self.candidate_matches.clear()

    def ntdll_read(self, uc, mapping, location, size):
        rip = uc.reg_read(ux.UC_X86_REG_RIP)
        matches = self.candidate_matches.get(rip)
        if matches is None:
            matches = [i for i, candidate in enumerate(self.candidates)
                       if any(left <= rip < right for left, right in candidate['ranges'])]
            if len(self.candidate_matches) < 4096:
                self.candidate_matches[rip] = matches
        for index in matches:
            self.candidates[index]['ntdll_reads'] += 1
            self.candidates[index]['ntdll_bytes_read'] += size
        rbp = uc.reg_read(ux.UC_X86_REG_RBP) if not matches else None
        key = (mapping['base'], rip, rbp)
        reader = self.ntdll_readers.get(key)
        new_reader = reader is None
        if reader is None:
            if len(self.ntdll_readers) >= 4096:
                self.untracked_ntdll_reads += 1
                return
            reader = {"mapping": mapping['name'], "mapping_base": mapping['base'],
                      "instruction": hex(rip), "rbp_at_read": hex(rbp) if rbp is not None else None,
                      "candidate_entries": [self.candidates[i]['entry'] for i in matches],
                      "reads": 0, "bytes_read": 0, "first_offset": location - int(mapping['base'], 16),
                      "last_offset": None, "min_offset": None, "max_offset": None}
            self.ntdll_readers[key] = reader
        offset = location - int(mapping['base'], 16)
        reader['reads'] += 1
        reader['bytes_read'] += size
        reader['last_offset'] = offset
        reader['min_offset'] = offset if reader['min_offset'] is None else min(reader['min_offset'], offset)
        reader['max_offset'] = offset + size if reader['max_offset'] is None else max(reader['max_offset'], offset + size)
        if new_reader:
            self.record('ntdll_reader', **reader)

    def save_ntdll_reads(self):
        report = {
            "candidates": [{key: value for key, value in candidate.items() if key != 'ranges'}
                           for candidate in self.candidates],
            "readers": sorted(self.ntdll_readers.values(), key=lambda row: row['reads'], reverse=True),
            "untracked_reads": self.untracked_ntdll_reads,
        }
        temporary = self.directory / 'ntdll-reads.json.tmp'
        temporary.write_text(json.dumps(report, indent=2), encoding='ascii')
        temporary.replace(self.directory / 'ntdll-reads.json')

    def hot_blocks(self, uc):
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        blocks = []
        for address, hits in self.block_hits.most_common(64):
            size = self.block_sizes[address]
            raw = self.read(uc, address, min(size, 256))
            instructions = []
            if raw is not None:
                instructions = [{"address": hex(ins.address), "mnemonic": ins.mnemonic,
                                 "operands": ins.op_str}
                                for ins in decoder.disasm(raw, address, count=32)]
            blocks.append({"address": hex(address), "hits": hits, "last_block_size": size,
                           "bytes": raw.hex() if raw is not None else None,
                           "instructions": instructions})
        return {"tracked_addresses": len(self.block_hits),
                "tracked_block_visits": sum(self.block_hits.values()),
                "untracked_block_visits": self.untracked_block_visits,
                "blocks": blocks}

    @staticmethod
    def read(uc, address, size):
        try:
            return bytes(uc.mem_read(address, size))
        except UcError:
            return None

    def snapshot(self, uc, extra_addresses=()):
        names = ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip', 'rflags')
        registers = {name: uc.reg_read(getattr(ux, 'UC_X86_REG_' + name.upper())) for name in names}
        regions = list(uc.mem_regions())
        memory = []
        seen = set()
        pointers = [(name, value, 512 if name in ('rsp', 'rsi') else 128)
                    for name, value in registers.items() if name != 'rflags']
        pointers += [(f'argument_{index + 1}', address, 128)
                     for index, address in enumerate(extra_addresses)]
        for label, address, size in pointers:
            if address in seen:
                continue
            seen.add(address)
            region = next((r for r in regions if r[0] <= address <= r[1]), None)
            if region is None:
                continue
            size = min(size, region[1] - address + 1)
            raw = self.read(uc, address, size)
            memory.append({"pointer": label, "address": hex(address),
                           "bytes": raw.hex() if raw is not None else None})
        return {"registers": {name: hex(value) for name, value in registers.items()},
                "memory": memory}

    def api_enter(self, uc, label, blocks):
        arguments = [uc.reg_read(reg) for reg in
                     (ux.UC_X86_REG_RCX, ux.UC_X86_REG_RDX, ux.UC_X86_REG_R8, ux.UC_X86_REG_R9)]
        rsp = uc.reg_read(ux.UC_X86_REG_RSP)
        for offset in range(0x28, 0x68, 8):
            raw = self.read(uc, rsp + offset, 8)
            arguments.append(int.from_bytes(raw, 'little') if raw is not None else 0)
        caller = self.read(uc, rsp, 8)
        self.record('api_enter', import_name=label, blocks=blocks,
                    return_address=int.from_bytes(caller, 'little') if caller else None,
                    argument_slots=[hex(value) for value in arguments],
                    **self.snapshot(uc, arguments))
        return arguments

    def api_return(self, uc, label, arguments, result, details, blocks):
        self.record('api_return', import_name=label, blocks=blocks, result=result,
                    details=details, **self.snapshot(uc, arguments))

    def watch_mapping(self, uc, address, size, name):
        state = {"name": name, "base": hex(address), "size": size,
                 "reads": 0, "writes": 0, "min_address": None, "max_address": None,
                 "samples": deque(maxlen=32)}
        self.mappings.append(state)
        self.record('mapped_file', name=name, address=address, size=size)

        def access(engine, access_type, location, width, value, user_data):
            field = 'writes' if access_type == UC_MEM_WRITE else 'reads'
            state[field] += 1
            if field == 'reads' and 'ntdll.dll' in name.lower():
                self.ntdll_read(engine, state, location, width)
            state['min_address'] = location if state['min_address'] is None else min(state['min_address'], location)
            state['max_address'] = location if state['max_address'] is None else max(state['max_address'], location)
            count = state[field]
            if count > 32 and count % 4096:
                return
            raw = self.read(engine, location, min(width, 32))
            sample = {"access": field, "access_number": count,
                      "rip": hex(engine.reg_read(ux.UC_X86_REG_RIP)),
                      "address": hex(location), "offset": hex(location - address),
                      "size": width, "bytes_before_access": raw.hex() if raw is not None else None}
            if access_type == UC_MEM_WRITE:
                sample['write_value'] = hex(value & ((1 << 64) - 1))
            state['samples'].append(sample)
            self.record('mapped_file_access', name=name, **sample)

        hook = uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, access,
                           begin=address, end=address + size - 1)
        self.hooks.append((uc, hook))

    def checkpoint(self, uc, **details):
        self.save_ntdll_reads()
        mappings = [{**state, "samples": list(state['samples'])} for state in self.mappings]
        state = {"elapsed_seconds": round(time.monotonic() - self.started, 3),
                 **format_report(details), **self.snapshot(uc), "mapped_files": mappings,
                 "hot_blocks": self.hot_blocks(uc)}
        temporary = self.directory / 'latest-state.json.tmp'
        temporary.write_text(json.dumps(state, indent=2), encoding='ascii')
        temporary.replace(self.directory / 'latest-state.json')
