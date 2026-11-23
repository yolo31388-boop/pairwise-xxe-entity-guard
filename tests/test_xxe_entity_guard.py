import pytest
import security.xxe_entity_guard as mod

CASES = [
    ("disable_dtd", (1, 2)),
    ("external_entity", (1, 2)),
    ("entity_depth", (1, 2)),
    ("schema_validate", (1, 2)),
    ("error_redact", (1, 2)),
    ("parser_feature", (1, 2)),
    ("oob_block", (1, 2)),
    ("size_limit", (1, 2)),
    ("timeout", (1, 2)),
    ("local_file_deny", (1, 2)),
    ("url_deny", (1, 2)),
    ("validation", (1, 2)),
    ("audit", (1, 2)),
    ("sanitize", (1, 2)),
    ("fallback", (1, 2)),
]

@pytest.mark.parametrize("fn_name,args", CASES)
def test_contract(fn_name, args):
    fn = getattr(mod, fn_name)
    assert fn(*args) is not None
