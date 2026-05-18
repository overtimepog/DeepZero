from ioctl_analyzer.dot import cfg_to_dot
from ioctl_analyzer.graphml import cfg_to_graphml
from ioctl_analyzer.ioctl import decode_ioctl, looks_like_ioctl
from ioctl_analyzer.models import AnalysisResult, BasicBlock, CFG, Instruction, IoctlCase
from ioctl_analyzer.analysis import RegState
from ioctl_analyzer.symbols import SymbolResolver


def test_ioctl_heuristic_accepts_ctl_code_shape():
    assert looks_like_ioctl(0x222003)
    assert looks_like_ioctl(0x80002010)
    decoded = decode_ioctl(0x222003)
    assert decoded.method_name == "METHOD_NEITHER"
    assert decoded.access_name == "FILE_ANY_ACCESS"


def test_ioctl_heuristic_rejects_small_values():
    assert not looks_like_ioctl(0xE)
    assert not looks_like_ioctl(0x100)


def test_json_serialization_uses_hex_addresses():
    ins = Instruction(address=0x1000, size=2, mnemonic="ret", op_str="", bytes_hex="c3")
    cfg = CFG(function=0x1000, blocks=[BasicBlock(start=0x1000, end=0x1002, instructions=[ins])], edges=[])
    case = IoctlCase(ioctl_code=0x222003, handler_va=0x140001000, source="unit", confidence="high", handler_symbol="HandleFoo", cfg=cfg)
    payload = case.to_json()
    assert payload["ioctl_code"] == "0x222003"
    assert payload["decoded_ioctl"]["method_name"] == "METHOD_NEITHER"
    assert payload["handler_va"] == "0x140001000"
    assert payload["handler_symbol"] == "HandleFoo"
    assert payload["cfg"]["blocks"][0]["start"] == "0x1000"


def test_dot_export_contains_nodes_and_edges():
    ins = Instruction(address=0x1000, size=2, mnemonic="jmp", op_str="0x1010", bytes_hex="eb0e")
    cfg = CFG(
        function=0x1000,
        blocks=[BasicBlock(start=0x1000, end=0x1002, instructions=[ins]), BasicBlock(start=0x1010, end=0x1011, instructions=[])],
        edges=[(0x1000, 0x1010, "branch")],
    )
    dot = cfg_to_dot(cfg)
    assert "digraph" in dot
    assert "n_1000 -> n_1010" in dot


def test_graphml_export_contains_nodes_and_edges():
    ins = Instruction(address=0x1000, size=2, mnemonic="jmp", op_str="0x1010", bytes_hex="eb0e")
    cfg = CFG(
        function=0x1000,
        blocks=[BasicBlock(start=0x1000, end=0x1002, instructions=[ins]), BasicBlock(start=0x1010, end=0x1011, instructions=[])],
        edges=[(0x1000, 0x1010, "branch")],
    )
    graphml = cfg_to_graphml(cfg)
    assert "<graphml" in graphml
    assert 'source="n_1000" target="n_1010"' in graphml


def test_reg_state_tags_clear_immediates():
    state = RegState()
    state.set("eax", 0x222003)
    assert state.get("rax") == 0x222003
    state.set_tag("rax", "IoControlCode")
    assert state.get("eax") is None
    assert state.get_tag("eax") == "IoControlCode"


def test_reg_state_stack_spill_tags_clear_stack_immediates():
    state = RegState()
    state.set_stack_immediate("rsp", 0x30, 0x222003)
    assert state.get_stack_immediate("rsp", 0x30) == 0x222003
    state.set_stack_tag("rsp", 0x30, "IoControlCode")
    assert state.get_stack_immediate("rsp", 0x30) is None
    assert state.get_stack_tag("rsp", 0x30) == "IoControlCode"


def test_symbol_resolver_parses_text_va(tmp_path):
    path = tmp_path / "symbols.txt"
    path.write_text("0x140001000 DeviceControl\n2000 RelativeName\n", encoding="utf-8")
    resolver = SymbolResolver.from_paths(0x140000000, symbol_paths=[path])
    assert resolver.resolve(0x140001000) == "DeviceControl"
    assert resolver.resolve(0x140000000 + 0x2000) == "RelativeName"


def test_analysis_result_serializes_wrapper_refs():
    result = AnalysisResult(
        image_path="driver.sys",
        machine="x64",
        image_base=0x140000000,
        entry_point_va=0x140001000,
        imports=[],
        io_create_device_refs=[],
        io_create_symbolic_link_refs=[],
        io_create_device_wrapper_refs=[{"callsite": "0x140001020", "wrapper": "0x140002000", "import": "IoCreateDevice"}],
        io_create_symbolic_link_wrapper_refs=[],
        device_control_dispatches=[],
    )
    payload = result.to_json()
    assert payload["io_create_device_wrapper_refs"][0]["wrapper"] == "0x140002000"
