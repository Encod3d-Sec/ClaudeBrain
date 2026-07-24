"""hunt-burp must carry the per-tool driver reference and wire the transport resolver."""
import pathlib

SKILL = (pathlib.Path(__file__).resolve().parents[1]
         / "skills" / "hunt" / "hunt-burp" / "SKILL.md").read_text()


def test_drives_each_burp_tool_by_name():
    # every load-bearing capability must name its real MCP tool so driving is frictionless
    for tool in ("create_repeater_tab", "send_to_intruder",
                 "generate_collaborator_payload", "set_user_options"):
        assert tool in SKILL, f"hunt-burp missing driver ref for {tool}"


def test_intruder_attack_types_named():
    low = SKILL.lower()
    assert "sniper" in low and "pitchfork" in low  # Intruder attack types, not a hand-rolled loop


def test_wires_transport_resolver():
    assert "burp-transport.sh" in SKILL
