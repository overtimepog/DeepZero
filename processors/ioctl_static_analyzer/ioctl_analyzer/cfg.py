from __future__ import annotations

from capstone import CS_GRP_JUMP, CS_GRP_RET

from .disasm import Disassembler, direct_imm_target
from .models import BasicBlock, CFG


CONDITIONAL_JUMPS = {
    "ja",
    "jae",
    "jb",
    "jbe",
    "jc",
    "jcxz",
    "je",
    "jecxz",
    "jg",
    "jge",
    "jl",
    "jle",
    "jna",
    "jnae",
    "jnb",
    "jnbe",
    "jnc",
    "jne",
    "jng",
    "jnge",
    "jnl",
    "jnle",
    "jno",
    "jnp",
    "jns",
    "jnz",
    "jo",
    "jp",
    "jpe",
    "jpo",
    "js",
    "jz",
}


def build_cfg(disasm: Disassembler, start_va: int, max_bytes: int = 0x4000) -> CFG:
    instrs = disasm.disassemble_function(start_va, max_bytes=max_bytes)
    if not instrs:
        return CFG(function=start_va)

    starts = {instrs[0].address}
    addr_to_ins = {ins.address: ins for ins in instrs}
    ordered_addrs = [ins.address for ins in instrs]
    next_by_addr = {
        ins.address: ordered_addrs[idx + 1] if idx + 1 < len(ordered_addrs) else None
        for idx, ins in enumerate(instrs)
    }

    for ins in instrs:
        if ins.group(CS_GRP_JUMP):
            target = direct_imm_target(ins)
            if target in addr_to_ins:
                starts.add(target)
            nxt = next_by_addr[ins.address]
            if nxt is not None and ins.mnemonic in CONDITIONAL_JUMPS:
                starts.add(nxt)
        elif ins.group(CS_GRP_RET):
            nxt = next_by_addr[ins.address]
            if nxt is not None:
                starts.add(nxt)

    sorted_starts = sorted(starts)
    blocks: list[BasicBlock] = []
    for idx, block_start in enumerate(sorted_starts):
        next_start = sorted_starts[idx + 1] if idx + 1 < len(sorted_starts) else None
        block_instrs = [
            Disassembler.to_model(ins)
            for ins in instrs
            if ins.address >= block_start and (next_start is None or ins.address < next_start)
        ]
        if not block_instrs:
            continue
        blocks.append(BasicBlock(start=block_start, end=block_instrs[-1].address + block_instrs[-1].size, instructions=block_instrs))

    block_by_start = {b.start: b for b in blocks}
    containing = {}
    for block in blocks:
        for ins in block.instructions:
            containing[ins.address] = block.start

    edges: list[tuple[int, int, str]] = []
    for block in blocks:
        last = addr_to_ins.get(block.instructions[-1].address)
        if last is None:
            continue
        nxt = next_by_addr[last.address]
        if last.group(CS_GRP_JUMP):
            target = direct_imm_target(last)
            if target in block_by_start:
                edges.append((block.start, target, "branch"))
            if last.mnemonic in CONDITIONAL_JUMPS and nxt in block_by_start:
                edges.append((block.start, nxt, "fallthrough"))
        elif not last.group(CS_GRP_RET) and nxt in block_by_start:
            edges.append((block.start, nxt, "fallthrough"))

    return CFG(function=start_va, blocks=blocks, edges=edges)

