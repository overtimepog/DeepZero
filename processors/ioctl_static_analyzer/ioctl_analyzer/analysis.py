from __future__ import annotations

import re
from dataclasses import dataclass, field

from capstone import CS_GRP_CALL
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

from .cfg import build_cfg
from .disasm import Disassembler, direct_imm_target, immediate_operands, mem_displacement_target, writes_memory
from .ioctl import looks_like_ioctl
from .models import AnalysisResult, DispatchRoutine, IRP_MJ_DEVICE_CONTROL, IoctlCase
from .pe_image import PEImage
from .symbols import SymbolResolver


X64_DRIVER_OBJECT_MAJOR_FUNCTION_OFFSET = 0x70
X86_DRIVER_OBJECT_MAJOR_FUNCTION_OFFSET = 0x38


@dataclass(slots=True)
class RegState:
    immediates: dict[str, int] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)
    stack_immediates: dict[tuple[str, int], int] = field(default_factory=dict)
    stack_tags: dict[tuple[str, int], str] = field(default_factory=dict)

    def set(self, reg: str, value: int) -> None:
        self.immediates[canonical_reg(reg)] = value

    def get(self, reg: str) -> int | None:
        return self.immediates.get(canonical_reg(reg))

    def set_tag(self, reg: str, tag: str) -> None:
        reg = canonical_reg(reg)
        self.tags[reg] = tag
        self.immediates.pop(reg, None)

    def get_tag(self, reg: str) -> str | None:
        return self.tags.get(canonical_reg(reg))

    def clear(self, reg: str) -> None:
        reg = canonical_reg(reg)
        self.immediates.pop(reg, None)
        self.tags.pop(reg, None)

    def set_stack_tag(self, base: str, disp: int, tag: str) -> None:
        key = (canonical_reg(base), disp)
        self.stack_tags[key] = tag
        self.stack_immediates.pop(key, None)

    def get_stack_tag(self, base: str, disp: int) -> str | None:
        return self.stack_tags.get((canonical_reg(base), disp))

    def set_stack_immediate(self, base: str, disp: int, value: int) -> None:
        key = (canonical_reg(base), disp)
        self.stack_immediates[key] = value
        self.stack_tags.pop(key, None)

    def get_stack_immediate(self, base: str, disp: int) -> int | None:
        return self.stack_immediates.get((canonical_reg(base), disp))

    def clear_stack(self, base: str, disp: int) -> None:
        key = (canonical_reg(base), disp)
        self.stack_tags.pop(key, None)
        self.stack_immediates.pop(key, None)

    def copy(self) -> "RegState":
        return RegState(
            immediates=dict(self.immediates),
            tags=dict(self.tags),
            stack_immediates=dict(self.stack_immediates),
            stack_tags=dict(self.stack_tags),
        )

    def merge(self, other: "RegState") -> "RegState":
        """Conservative join: keep only facts that agree on all incoming paths."""

        return RegState(
            immediates={k: v for k, v in self.immediates.items() if other.immediates.get(k) == v},
            tags={k: v for k, v in self.tags.items() if other.tags.get(k) == v},
            stack_immediates={k: v for k, v in self.stack_immediates.items() if other.stack_immediates.get(k) == v},
            stack_tags={k: v for k, v in self.stack_tags.items() if other.stack_tags.get(k) == v},
        )

    def fingerprint(self) -> tuple:
        return (
            tuple(sorted(self.immediates.items())),
            tuple(sorted(self.tags.items())),
            tuple(sorted(self.stack_immediates.items())),
            tuple(sorted(self.stack_tags.items())),
        )


@dataclass(slots=True)
class RawBlock:
    start: int
    instructions: list
    successors: list[int] = field(default_factory=list)


def canonical_reg(reg: str) -> str:
    aliases = {
        "eax": "rax",
        "ax": "rax",
        "al": "rax",
        "ebx": "rbx",
        "bx": "rbx",
        "bl": "rbx",
        "ecx": "rcx",
        "cx": "rcx",
        "cl": "rcx",
        "edx": "rdx",
        "dx": "rdx",
        "dl": "rdx",
        "esi": "rsi",
        "edi": "rdi",
        "esp": "rsp",
        "ebp": "rbp",
        "r8d": "r8",
        "r9d": "r9",
        "r10d": "r10",
        "r11d": "r11",
    }
    return aliases.get(reg, reg)


class DriverAnalyzer:
    def __init__(self, image: PEImage, symbols: SymbolResolver | None = None):
        self.image = image
        self.disasm = Disassembler(image)
        self.symbols = symbols or SymbolResolver()
        self.warnings: list[str] = []

    def analyze(self, include_cfg: bool = True) -> AnalysisResult:
        imports = self.image.imports()

        # Single-pass scan of all executable sections for import call refs.
        # Previously find_import_call_refs was called twice (once per import),
        # each disassembling the entire .text section from scratch. For large
        # drivers (camera, GPU) with 500KB+ .text sections this was the #1
        # bottleneck — 2x full Capstone disasm before any analysis started.
        io_create_device_refs, io_create_symbolic_link_refs = \
            self._find_import_call_refs_batch(["IoCreateDevice", "IoCreateSymbolicLink"])

        init_functions = self._discover_initialization_functions(self.image.entry_point_va, max_depth=3)
        io_create_device_wrapper_refs = self.find_import_wrapper_refs("IoCreateDevice", init_functions)
        io_create_symbolic_link_wrapper_refs = self.find_import_wrapper_refs("IoCreateSymbolicLink", init_functions)
        dispatches = self.find_device_control_dispatches(include_cfg=include_cfg)
        return AnalysisResult(
            image_path=str(self.image.path),
            machine=self.image.machine_name,
            image_base=self.image.image_base,
            entry_point_va=self.image.entry_point_va,
            imports=imports,
            io_create_device_refs=io_create_device_refs,
            io_create_symbolic_link_refs=io_create_symbolic_link_refs,
            io_create_device_wrapper_refs=io_create_device_wrapper_refs,
            io_create_symbolic_link_wrapper_refs=io_create_symbolic_link_wrapper_refs,
            device_control_dispatches=dispatches,
            warnings=[*self.warnings, *self.symbols.warnings],
            symbols=self.symbols.symbols,
        )

    def find_import_call_refs(self, import_name: str) -> list[int]:
        iat = self.image.import_iat_va(import_name)
        refs: set[int] = set()
        if iat is None:
            self.warnings.append(f"Import {import_name} was not found; refs may be resolved dynamically or statically linked.")
            return []
        for _, instrs in self.disasm.disassemble_section_streams():
            for ins in instrs:
                if not ins.group(CS_GRP_CALL):
                    continue
                direct = direct_imm_target(ins)
                mem = mem_displacement_target(ins)
                if direct == iat or mem == iat:
                    refs.add(int(ins.address))
        return sorted(refs)

    def _find_import_call_refs_batch(self, import_names: list[str]) -> list[list[int]]:
        """Single-pass scan for multiple import call refs. Disassembles each
        executable section ONCE and checks all IAT addresses simultaneously.
        For large .text sections (camera/GPU drivers), this avoids redundant
        full-disassembly passes that were the #1 perf bottleneck."""
        iats: dict[str, int | None] = {}
        refs: dict[str, set[int]] = {}
        for name in import_names:
            iat = self.image.import_iat_va(name)
            iats[name] = iat
            refs[name] = set()
            if iat is None:
                self.warnings.append(
                    f"Import {name} was not found; refs may be resolved "
                    f"dynamically or statically linked."
                )

        for _, instrs in self.disasm.disassemble_section_streams():
            for ins in instrs:
                if not ins.group(CS_GRP_CALL):
                    continue
                direct = direct_imm_target(ins)
                mem = mem_displacement_target(ins)
                for name, iat in iats.items():
                    if iat is not None and (direct == iat or mem == iat):
                        refs[name].add(int(ins.address))

        return [sorted(refs[name]) for name in import_names]

    def find_import_wrapper_refs(self, import_name: str, init_functions: set[int]) -> list[dict[str, str]]:
        """Find init helper calls that eventually call a target import.

        Direct import call-site reporting is useful, but many drivers hide WDM setup in
        `CreateDevice` / `InitDeviceObjects` wrappers. This reports calls from the discovered
        DriverEntry initialization slice into local functions that directly call the requested
        import.
        """

        iat = self.image.import_iat_va(import_name)
        if iat is None:
            return []

        executable = self.image.executable_ranges()
        wrappers: set[int] = set()
        for function_va in init_functions:
            instrs = self.disasm.disassemble_function(function_va, max_bytes=0x8000)
            for ins in instrs:
                if not ins.group(CS_GRP_CALL):
                    continue
                direct = direct_imm_target(ins)
                mem = mem_displacement_target(ins)
                if direct == iat or mem == iat:
                    wrappers.add(function_va)

        refs: list[dict[str, str]] = []
        for caller_va in init_functions:
            instrs = self.disasm.disassemble_function(caller_va, max_bytes=0x8000)
            for ins in instrs:
                if not ins.group(CS_GRP_CALL):
                    continue
                target = direct_imm_target(ins)
                if target is None or target not in wrappers or target == caller_va:
                    continue
                if not any(start <= target < end for start, end in executable):
                    continue
                refs.append(
                    {
                        "callsite": hex(int(ins.address)),
                        "caller": hex(caller_va),
                        "caller_symbol": self.symbols.resolve(caller_va) or "",
                        "wrapper": hex(target),
                        "wrapper_symbol": self.symbols.resolve(target) or "",
                        "import": import_name,
                    }
                )
        return refs

    def find_device_control_dispatches(self, include_cfg: bool) -> list[DispatchRoutine]:
        candidate_functions = self._discover_initialization_functions(self.image.entry_point_va, max_depth=3)
        routines: dict[int, DispatchRoutine] = {}
        for function_va in sorted(candidate_functions):
            instrs = self.disasm.disassemble_function(function_va, max_bytes=0x8000)
            for idx, ins in enumerate(instrs):
                maybe = self._major_function_assignment(instrs, idx)
                if maybe is None:
                    continue
                handler, evidence = maybe
                dispatch = routines.setdefault(handler, DispatchRoutine(routine_va=handler, routine_symbol=self.symbols.resolve(handler)))
                dispatch.evidence.append(f"{evidence}; discovered while scanning init function 0x{function_va:x}")

            for handler, evidence in self._wrapper_dispatch_assignments(function_va, instrs, candidate_functions):
                dispatch = routines.setdefault(handler, DispatchRoutine(routine_va=handler, routine_symbol=self.symbols.resolve(handler)))
                dispatch.evidence.append(evidence)

        if not routines:
            self.warnings.append(
                "No direct DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] assignment was found in DriverEntry. "
                "Try increasing max disassembly limits or inspect wrapper initialization routines."
            )

        for dispatch in routines.values():
            dispatch.ioctl_cases = self.recover_ioctl_cases(dispatch.routine_va, include_cfg=include_cfg)
            for case in dispatch.ioctl_cases:
                case.handler_symbol = self.symbols.resolve(case.handler_va)
            if include_cfg:
                dispatch.cfg = build_cfg(self.disasm, dispatch.routine_va)
        return list(routines.values())

    def _discover_initialization_functions(self, root_va: int, max_depth: int = 2) -> set[int]:
        """Discover DriverEntry and direct helper routines likely used during initialization.

        This intentionally stays conservative: it follows direct calls that target executable
        sections inside the same image, which catches common DriverEntry helper wrappers without
        turning the analyzer into a whole-program recursive descent disassembler.
        """

        discovered: set[int] = set()
        frontier: list[tuple[int, int]] = [(root_va, 0)]
        executable = self.image.executable_ranges()

        while frontier:
            function_va, depth = frontier.pop()
            if function_va in discovered or depth > max_depth:
                continue
            discovered.add(function_va)
            instrs = self.disasm.disassemble_function(function_va, max_bytes=0x8000)
            for ins in instrs:
                if not ins.group(CS_GRP_CALL):
                    continue
                target = direct_imm_target(ins)
                if target is None:
                    continue
                if not any(start <= target < end for start, end in executable):
                    continue
                if target not in discovered:
                    frontier.append((target, depth + 1))

        return discovered

    def _major_function_assignment(self, instrs: list, idx: int) -> tuple[int, str] | None:
        ins = instrs[idx]
        if not writes_memory(ins) or len(ins.operands) < 2:
            return None

        dst = ins.operands[0]
        src = ins.operands[1]
        if dst.type != X86_OP_MEM:
            return None

        major_base = X64_DRIVER_OBJECT_MAJOR_FUNCTION_OFFSET if self.image.is_64bit else X86_DRIVER_OBJECT_MAJOR_FUNCTION_OFFSET
        ptr_size = 8 if self.image.is_64bit else 4
        expected_disp = major_base + IRP_MJ_DEVICE_CONTROL * ptr_size
        mem = dst.mem
        if mem.disp != expected_disp:
            return None

        # x64 DriverEntry first argument is DriverObject in rcx; x86 is usually [esp+4].
        base_name = ins.reg_name(mem.base) if mem.base else ""
        if self.image.is_64bit and canonical_reg(base_name) != "rcx":
            # The DriverObject pointer may have been copied first; accept it, but lower confidence.
            evidence_note = f"store to MajorFunction[0x{IRP_MJ_DEVICE_CONTROL:x}] via {base_name or 'unknown base'}"
        else:
            evidence_note = f"store to DriverObject->MajorFunction[0x{IRP_MJ_DEVICE_CONTROL:x}]"

        handler = None
        if src.type == X86_OP_IMM:
            handler = int(src.imm)
        elif src.type == X86_OP_MEM:
            target = mem_displacement_target(ins)
            if target is not None:
                try:
                    handler = self.image.read_pointer(target)
                except Exception:
                    handler = None
        else:
            reg_name = ins.reg_name(src.reg) if getattr(src, "reg", 0) else ""
            handler = self._backtrack_register_immediate(instrs, idx, reg_name)

        if handler is None:
            self.warnings.append(f"Potential device-control dispatch assignment at 0x{ins.address:x}, but handler target was not resolved.")
            return None

        return handler, f"{evidence_note} at 0x{ins.address:x}"

    def _major_function_assignment_source_register(self, instrs: list, idx: int) -> tuple[str, str] | None:
        ins = instrs[idx]
        if not writes_memory(ins) or len(ins.operands) < 2:
            return None
        dst = ins.operands[0]
        src = ins.operands[1]
        if dst.type != X86_OP_MEM or not getattr(src, "reg", 0):
            return None
        major_base = X64_DRIVER_OBJECT_MAJOR_FUNCTION_OFFSET if self.image.is_64bit else X86_DRIVER_OBJECT_MAJOR_FUNCTION_OFFSET
        ptr_size = 8 if self.image.is_64bit else 4
        expected_disp = major_base + IRP_MJ_DEVICE_CONTROL * ptr_size
        if dst.mem.disp != expected_disp:
            return None
        reg_name = canonical_reg(ins.reg_name(src.reg))
        evidence = f"wrapper stores argument register {reg_name} into MajorFunction[0x{IRP_MJ_DEVICE_CONTROL:x}] at 0x{ins.address:x}"
        return reg_name, evidence

    def _wrapper_dispatch_assignments(self, caller_va: int, caller_instrs: list, candidate_functions: set[int]) -> list[tuple[int, str]]:
        if not self.image.is_64bit:
            return []
        wrapper_arg_sources: dict[int, list[tuple[str, str]]] = {}
        for target_va in candidate_functions:
            if target_va == caller_va:
                continue
            target_instrs = self.disasm.disassemble_function(target_va, max_bytes=0x4000)
            sources: list[tuple[str, str]] = []
            for idx in range(len(target_instrs)):
                source = self._major_function_assignment_source_register(target_instrs, idx)
                if source is not None:
                    sources.append(source)
            if sources:
                wrapper_arg_sources[target_va] = sources

        recovered: list[tuple[int, str]] = []
        for idx, ins in enumerate(caller_instrs):
            if not ins.group(CS_GRP_CALL):
                continue
            target = direct_imm_target(ins)
            if target is None or target not in wrapper_arg_sources:
                continue
            for arg_reg, wrapper_evidence in wrapper_arg_sources[target]:
                handler = self._backtrack_register_immediate(caller_instrs, idx, arg_reg, window=24)
                if handler is None:
                    continue
                recovered.append(
                    (
                        handler,
                        f"dispatch handler 0x{handler:x} passed in {arg_reg} to wrapper 0x{target:x} at callsite 0x{ins.address:x}; {wrapper_evidence}",
                    )
                )
        return recovered

    def _backtrack_register_immediate(self, instrs: list, idx: int, reg_name: str, window: int = 16) -> int | None:
        wanted = canonical_reg(reg_name)
        for prev in reversed(instrs[max(0, idx - window):idx]):
            if not prev.operands:
                continue
            if prev.mnemonic not in {"mov", "lea"}:
                continue
            dst = prev.operands[0]
            if not getattr(dst, "reg", 0):
                continue
            dst_name = canonical_reg(prev.reg_name(dst.reg))
            if dst_name != wanted:
                continue
            if len(prev.operands) < 2:
                continue
            src = prev.operands[1]
            if src.type == X86_OP_IMM:
                return int(src.imm)
            if src.type == X86_OP_MEM:
                return mem_displacement_target(prev)
        return None

    def recover_ioctl_cases(self, routine_va: int, include_cfg: bool) -> list[IoctlCase]:
        instrs = self.disasm.disassemble_function(routine_va, max_bytes=0x10000)
        cases: dict[tuple[int | None, int], IoctlCase] = {}

        for case in self._recover_cmp_branch_cases(instrs):
            cases[(case.ioctl_code, case.handler_va)] = case

        for case in self._recover_jump_table_cases(instrs):
            cases[(case.ioctl_code, case.handler_va)] = case

        if include_cfg:
            for case in cases.values():
                case.cfg = build_cfg(self.disasm, case.handler_va, max_bytes=0x4000)

        return sorted(cases.values(), key=lambda c: ((c.ioctl_code if c.ioctl_code is not None else 0xFFFFFFFF), c.handler_va))

    def _recover_cmp_branch_cases(self, instrs: list) -> list[IoctlCase]:
        cases: list[IoctlCase] = []
        ioctl_cmp_sources = self._track_ioctl_compare_sources(instrs)
        for idx, ins in enumerate(instrs):
            if ins.mnemonic != "cmp":
                continue
            imm_values = [v for v in immediate_operands(ins) if looks_like_ioctl(v)]
            if not imm_values:
                continue
            ioctl = imm_values[0]
            source_note = ioctl_cmp_sources.get(ins.address)
            branch_target = None
            for look in instrs[idx + 1:idx + 5]:
                if look.mnemonic in {"je", "jz"}:
                    branch_target = direct_imm_target(look)
                    break
                if look.mnemonic.startswith("j") and look.mnemonic not in {"jne", "jnz"}:
                    break
            if branch_target is not None:
                confidence = "high" if source_note else "medium"
                source = f"cmp/branch at 0x{ins.address:x}"
                if source_note:
                    source += f" using {source_note}"
                cases.append(IoctlCase(ioctl_code=ioctl, handler_va=branch_target, source=source, confidence=confidence))
        return cases

    def _track_ioctl_compare_sources(self, instrs: list) -> dict[int, str]:
        """Track common data-flow from IRP stack locations to IOCTL comparisons.

        This is intentionally lightweight and linear. It recognizes the common dispatch pattern:

        - `IoGetCurrentIrpStackLocation(Irp)` followed by return register use.
        - Loads from `_IO_STACK_LOCATION.Parameters.DeviceIoControl.IoControlCode`.
        - Moves through temporary registers before a `cmp reg, imm` or `cmp imm, reg`.

        The pass does not attempt alias-perfect recovery. It only annotates comparisons where
        there is clear evidence that one operand is derived from the IOCTL field.
        """

        comparisons: dict[int, str] = {}
        io_get_stack_iat = self.image.import_iat_va("IoGetCurrentIrpStackLocation")
        ioctl_offsets = {0x10, 0x18} if self.image.is_64bit else {0x0C, 0x10}
        blocks = self._raw_blocks(instrs)
        if not blocks:
            return comparisons

        in_states: dict[int, RegState] = {blocks[0].start: RegState()}
        out_fingerprints: dict[int, tuple] = {}
        block_by_start = {block.start: block for block in blocks}
        worklist = [blocks[0].start]

        while worklist:
            block_start = worklist.pop(0)
            block = block_by_start[block_start]
            state = in_states[block_start].copy()
            before = state.fingerprint()
            self._transfer_ioctl_block(block.instructions, state, comparisons, io_get_stack_iat, ioctl_offsets)
            after = state.fingerprint()
            if out_fingerprints.get(block_start) == after and before == in_states[block_start].fingerprint():
                continue
            out_fingerprints[block_start] = after

            for succ in block.successors:
                previous = in_states.get(succ)
                merged = state.copy() if previous is None else previous.merge(state)
                if previous is None or merged.fingerprint() != previous.fingerprint():
                    in_states[succ] = merged
                    worklist.append(succ)

        return comparisons

    def _transfer_ioctl_block(
        self,
        instrs: list,
        state: RegState,
        comparisons: dict[int, str],
        io_get_stack_iat: int | None,
        ioctl_offsets: set[int],
    ) -> None:
        for ins in instrs:
            if ins.group(CS_GRP_CALL):
                target = direct_imm_target(ins)
                mem = mem_displacement_target(ins)
                if io_get_stack_iat is not None and (target == io_get_stack_iat or mem == io_get_stack_iat):
                    state.set_tag("rax" if self.image.is_64bit else "eax", "IO_STACK_LOCATION")
                else:
                    self._clear_volatile_after_call(state)
                continue

            if not ins.operands:
                continue

            if ins.mnemonic in {"mov", "movzx", "movsxd", "lea"} and len(ins.operands) >= 2:
                dst, src = ins.operands[0], ins.operands[1]
                if getattr(dst, "reg", 0):
                    dst_reg = ins.reg_name(dst.reg)
                    if src.type == X86_OP_IMM:
                        state.set(dst_reg, int(src.imm))
                    elif getattr(src, "reg", 0):
                        src_reg = ins.reg_name(src.reg)
                        tag = state.get_tag(src_reg)
                        if tag:
                            state.set_tag(dst_reg, tag)
                        else:
                            value = state.get(src_reg)
                            if value is not None:
                                state.set(dst_reg, value)
                            else:
                                state.clear(dst_reg)
                    elif src.type == X86_OP_MEM:
                        tag = self._memory_load_tag(ins, src, state, ioctl_offsets)
                        if tag:
                            state.set_tag(dst_reg, tag)
                        else:
                            state.clear(dst_reg)
                    else:
                        state.clear(dst_reg)
                elif dst.type == X86_OP_MEM:
                    stack_key = self._stack_slot_key(ins, dst)
                    if stack_key is not None:
                        base, disp = stack_key
                        if src.type == X86_OP_IMM:
                            state.set_stack_immediate(base, disp, int(src.imm))
                        elif getattr(src, "reg", 0):
                            src_reg = ins.reg_name(src.reg)
                            tag = state.get_tag(src_reg)
                            value = state.get(src_reg)
                            if tag:
                                state.set_stack_tag(base, disp, tag)
                            elif value is not None:
                                state.set_stack_immediate(base, disp, value)
                            else:
                                state.clear_stack(base, disp)
                        else:
                            state.clear_stack(base, disp)
                continue

            if ins.mnemonic == "cmp":
                tagged = self._cmp_ioctl_operand_tag(ins, state, ioctl_offsets)
                if tagged:
                    comparisons[int(ins.address)] = tagged
                continue

            # Basic destructive arithmetic usually means the register is no longer a clean IOCTL value.
            if ins.mnemonic in {"add", "sub", "xor", "and", "or", "shl", "shr", "sar", "imul"} and ins.operands and getattr(ins.operands[0], "reg", 0):
                state.clear(ins.reg_name(ins.operands[0].reg))

    def _raw_blocks(self, instrs: list) -> list[RawBlock]:
        if not instrs:
            return []
        addr_to_ins = {ins.address: ins for ins in instrs}
        ordered = [ins.address for ins in instrs]
        next_by_addr = {
            ins.address: ordered[idx + 1] if idx + 1 < len(ordered) else None
            for idx, ins in enumerate(instrs)
        }
        leaders = {ordered[0]}
        for ins in instrs:
            if ins.mnemonic.startswith("j"):
                target = direct_imm_target(ins)
                if target in addr_to_ins:
                    leaders.add(target)
                nxt = next_by_addr[ins.address]
                if nxt is not None and ins.mnemonic != "jmp":
                    leaders.add(nxt)
            elif ins.mnemonic.startswith("ret"):
                nxt = next_by_addr[ins.address]
                if nxt is not None:
                    leaders.add(nxt)

        sorted_leaders = sorted(leaders)
        blocks: list[RawBlock] = []
        for idx, start in enumerate(sorted_leaders):
            end = sorted_leaders[idx + 1] if idx + 1 < len(sorted_leaders) else None
            block_instrs = [ins for ins in instrs if ins.address >= start and (end is None or ins.address < end)]
            if not block_instrs:
                continue
            blocks.append(RawBlock(start=start, instructions=block_instrs))

        block_starts = {block.start for block in blocks}
        for block in blocks:
            last = block.instructions[-1]
            nxt = next_by_addr[last.address]
            if last.mnemonic.startswith("j"):
                target = direct_imm_target(last)
                if target in block_starts:
                    block.successors.append(target)
                if last.mnemonic != "jmp" and nxt in block_starts:
                    block.successors.append(nxt)
            elif not last.mnemonic.startswith("ret") and nxt in block_starts:
                block.successors.append(nxt)
        return blocks

    def _memory_load_tag(self, ins, mem_operand, state: RegState, ioctl_offsets: set[int]) -> str | None:
        mem = mem_operand.mem
        base = ins.reg_name(mem.base) if mem.base else ""
        base_tag = state.get_tag(base) if base else None
        stack_key = self._stack_slot_key(ins, mem_operand)
        if stack_key is not None:
            tag = state.get_stack_tag(*stack_key)
            if tag:
                return f"stack-spilled {tag}([{stack_key[0]}{stack_key[1]:+x}])"

        if base_tag == "IO_STACK_LOCATION" and mem.disp in ioctl_offsets:
            return f"IO_STACK_LOCATION.Parameters.DeviceIoControl.IoControlCode(+0x{mem.disp:x})"

        # Some compilers keep the stack-location pointer in a temporary then load via [tmp + offset].
        # If the base was not tagged, still accept canonical offsets as weak evidence only when the
        # instruction width is compatible with a ULONG load.
        if mem.disp in ioctl_offsets and getattr(ins, "operands", None):
            return f"possible IoControlCode field load(+0x{mem.disp:x})"
        return None

    def _cmp_ioctl_operand_tag(self, ins, state: RegState, ioctl_offsets: set[int]) -> str | None:
        for op in ins.operands:
            if getattr(op, "reg", 0):
                tag = state.get_tag(ins.reg_name(op.reg))
                if tag and "IoControlCode" in tag:
                    return tag
            elif op.type == X86_OP_MEM:
                tag = self._memory_load_tag(ins, op, state, ioctl_offsets)
                if tag:
                    return tag
        return None

    def _stack_slot_key(self, ins, mem_operand) -> tuple[str, int] | None:
        mem = mem_operand.mem
        if not mem.base or mem.index:
            return None
        base = canonical_reg(ins.reg_name(mem.base))
        if base not in {"rsp", "rbp", "esp", "ebp"}:
            return None
        # Ignore very large displacements to avoid accidentally treating globals as locals.
        if not -0x10000 <= mem.disp <= 0x10000:
            return None
        return base, int(mem.disp)

    def _clear_volatile_after_call(self, state: RegState) -> None:
        volatile = ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"] if self.image.is_64bit else ["eax", "ecx", "edx"]
        for reg in volatile:
            state.clear(reg)

    def _recover_jump_table_cases(self, instrs: list) -> list[IoctlCase]:
        cases: list[IoctlCase] = []
        for idx, ins in enumerate(instrs):
            if not (ins.mnemonic.startswith("jmp") and ins.operands and ins.operands[0].type == X86_OP_MEM):
                continue
            table_va = mem_displacement_target(ins)
            if table_va is None:
                # RIP-relative scaled-index jump tables often expose the table displacement through op_str.
                table_va = self._extract_probable_va(ins.op_str)
            if table_va is None:
                continue
            bounds = self._infer_switch_bounds(instrs, idx)
            base_ioctl = self._infer_switch_base_ioctl(instrs, idx)
            targets = self._read_jump_table(table_va, bounds.max_cases)
            for case_idx, target in enumerate(targets):
                ioctl = base_ioctl + case_idx if base_ioctl is not None else None
                cases.append(
                    IoctlCase(
                        ioctl_code=ioctl if ioctl is None or looks_like_ioctl(ioctl) else None,
                        handler_va=target,
                        source=f"jump-table 0x{table_va:x} index {case_idx}",
                        confidence="low" if ioctl is None else "medium",
                    )
                )
        cases.extend(self._recover_relative_jump_table_cases(instrs))
        return cases

    def _recover_relative_jump_table_cases(self, instrs: list) -> list[IoctlCase]:
        cases: list[IoctlCase] = []
        for idx, ins in enumerate(instrs):
            if not ins.mnemonic.startswith("jmp"):
                continue
            if not ins.operands or ins.operands[0].type == X86_OP_MEM:
                continue

            table_va = self._find_recent_lea_table_base(instrs, idx)
            if table_va is None:
                continue

            bounds = self._infer_switch_bounds(instrs, idx)
            base_ioctl = self._infer_switch_base_ioctl(instrs, idx)
            targets = self._read_relative_jump_table(table_va, bounds.max_cases)
            for case_idx, target in enumerate(targets):
                ioctl = base_ioctl + case_idx if base_ioctl is not None else None
                cases.append(
                    IoctlCase(
                        ioctl_code=ioctl if ioctl is None or looks_like_ioctl(ioctl) else None,
                        handler_va=target,
                        source=f"relative jump-table 0x{table_va:x} index {case_idx}",
                        confidence="low" if ioctl is None else "medium",
                    )
                )
        return cases

    def _find_recent_lea_table_base(self, instrs: list, idx: int) -> int | None:
        # MSVC x64 commonly lowers switches as:
        #   lea   rax, [rip + table]
        #   movsxd rcx, dword ptr [rax + index*4]
        #   add   rcx, rax
        #   jmp   rcx
        # The table contains signed 32-bit offsets relative to the table base.
        for prev in reversed(instrs[max(0, idx - 16):idx]):
            if prev.mnemonic != "lea":
                continue
            table_va = mem_displacement_target(prev)
            if table_va is None:
                continue
            section = self.image.section_for_va(table_va)
            if section is not None and section.is_readable:
                return table_va
        return None

    def _extract_probable_va(self, op_str: str) -> int | None:
        candidates = [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", op_str)]
        for candidate in candidates:
            if self.image.section_for_va(candidate) is not None:
                return candidate
        return None

    @dataclass(slots=True)
    class SwitchBounds:
        max_cases: int = 64

    def _infer_switch_bounds(self, instrs: list, idx: int) -> SwitchBounds:
        max_cases = 64
        for prev in reversed(instrs[max(0, idx - 20):idx]):
            if prev.mnemonic == "cmp":
                values = [v for v in immediate_operands(prev) if 0 <= v < 512]
                if values:
                    max_cases = min(values[-1] + 1, 512)
                    break
        return self.SwitchBounds(max_cases=max_cases)

    def _infer_switch_base_ioctl(self, instrs: list, idx: int) -> int | None:
        for prev in reversed(instrs[max(0, idx - 30):idx]):
            if prev.mnemonic in {"sub", "add"}:
                values = [v for v in immediate_operands(prev) if looks_like_ioctl(v)]
                if values:
                    return values[-1]
            if prev.mnemonic == "cmp":
                values = [v for v in immediate_operands(prev) if looks_like_ioctl(v)]
                if values:
                    return values[-1]
        return None

    def _read_jump_table(self, table_va: int, max_cases: int) -> list[int]:
        ptr_size = 8 if self.image.is_64bit else 4
        targets: list[int] = []
        for idx in range(max_cases):
            try:
                value = self.image.read_pointer(table_va + idx * ptr_size)
            except Exception:
                break
            if not any(start <= value < end for start, end in self.image.executable_ranges()):
                break
            targets.append(value)
        return targets

    def _read_relative_jump_table(self, table_va: int, max_cases: int) -> list[int]:
        targets: list[int] = []
        for idx in range(max_cases):
            try:
                raw = self.image.read_va(table_va + idx * 4, 4)
            except Exception:
                break
            rel = int.from_bytes(raw, "little", signed=True)
            target = table_va + rel
            if not any(start <= target < end for start, end in self.image.executable_ranges()):
                break
            targets.append(target)
        return targets
