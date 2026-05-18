from __future__ import annotations

from collections.abc import Iterable

from capstone import Cs, CS_ARCH_X86, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_MODE_32, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from .models import Instruction
from .pe_image import PEImage


class Disassembler:
    def __init__(self, image: PEImage):
        self.image = image
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64 if image.is_64bit else CS_MODE_32)
        self.cs.detail = True
        self.cs.skipdata = True

    def disassemble_bytes(self, va: int, data: bytes) -> list:
        return list(self.cs.disasm(data, va))

    def disassemble_range(self, va: int, size: int) -> list:
        return self.disassemble_bytes(va, self.image.read_va(va, size))

    def disassemble_section_streams(self) -> Iterable[tuple[int, list]]:
        for va, data in self.image.iter_executable_bytes():
            yield va, self.disassemble_bytes(va, data)

    def disassemble_function(self, start_va: int, max_bytes: int = 0x4000) -> list:
        section = self.image.section_for_va(start_va)
        if section is None:
            return []
        size = min(max_bytes, section.end_va - start_va)
        instrs = self.disassemble_range(start_va, size)
        trimmed = []
        for ins in instrs:
            trimmed.append(ins)
            if ins.group(CS_GRP_RET):
                break
        return trimmed

    @staticmethod
    def to_model(ins) -> Instruction:
        groups: list[str] = []
        if ins.group(CS_GRP_CALL):
            groups.append("call")
        if ins.group(CS_GRP_JUMP):
            groups.append("jump")
        if ins.group(CS_GRP_RET):
            groups.append("ret")
        return Instruction(
            address=int(ins.address),
            size=int(ins.size),
            mnemonic=ins.mnemonic,
            op_str=ins.op_str,
            bytes_hex=bytes(ins.bytes).hex(),
            groups=tuple(groups),
        )


def direct_imm_target(ins) -> int | None:
    if not ins.operands:
        return None
    op = ins.operands[0]
    if op.type == X86_OP_IMM:
        return int(op.imm)
    return None


def mem_displacement_target(ins) -> int | None:
    if not ins.operands:
        return None
    for op in ins.operands:
        if op.type == X86_OP_MEM:
            mem = op.mem
            if mem.base == 0 and mem.index == 0 and mem.disp:
                return int(mem.disp)
            # RIP-relative memory operands on x64 use base register RIP.
            if ins.reg_name(mem.base) == "rip":
                return int(ins.address + ins.size + mem.disp)
    return None


def writes_memory(ins) -> bool:
    if not ins.mnemonic.startswith("mov"):
        return False
    return bool(ins.operands and ins.operands[0].type == X86_OP_MEM)


def immediate_operands(ins) -> list[int]:
    return [int(op.imm) for op in ins.operands if op.type == X86_OP_IMM]


def register_operands(ins) -> list[str]:
    regs = []
    for op in ins.operands:
        if op.type == X86_OP_REG:
            regs.append(ins.reg_name(op.reg))
    return regs

