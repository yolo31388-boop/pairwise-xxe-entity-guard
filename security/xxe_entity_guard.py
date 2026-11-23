"""XXE-hardened XML parsing.

Threat model
------------
Attacker-controlled XML reaches a parser that (a) resolves the DTD,
(b) loads external entities (``file://``, ``http://``, ...), (c) echoes
parser errors that contain file contents, or (d) exfiltrates data
out-of-band (OOB).  Any of these turns parsing into local file
disclosure or SSRF.

Defence
-------
* A DOCTYPE / DTD is rejected outright.  Without a DTD there are no
  entity declarations to expand, so billion-laughs, external-entity and
  parameter-entity attacks have no attack surface at all.
* External entities, parameter entities, local files and network URLs
  are denied independently as defence in depth.
* Element depth, entity depth, input size and parse time are bounded.
* A document can optionally be validated against a small declarative
  schema.
* Failures are mapped to stable error codes.  The original exception
  text (which may quote document content) is never returned to the
  caller.

``parse_secure`` is the authoritative entry point; the individual
``disable_dtd``/``external_entity``/... helpers are supplemental guards
that can be used to pre-screen input or to assert policy in tests.
"""

from __future__ import annotations

import re
import time
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from xml.etree import ElementTree as ET
from xml.parsers import expat

__all__ = [
    "DEFAULT_POLICY",
    "DEFAULT_SCHEMA",
    "ElementRule",
    "GuardResult",
    "ParseOutcome",
    "SanitizedDocument",
    "Schema",
    "XmlSecurityPolicy",
    "audit",
    "disable_dtd",
    "entity_depth",
    "error_redact",
    "external_entity",
    "fallback",
    "local_file_deny",
    "oob_block",
    "parse_secure",
    "parser_feature",
    "sanitize",
    "schema_validate",
    "size_limit",
    "timeout",
    "url_deny",
    "validation",
]

# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

MAX_INPUT_BYTES = 1 << 20  # 1 MiB
MAX_ELEMENT_DEPTH = 64
DEFAULT_TIMEOUT = 5.0


@dataclass(frozen=True)
class XmlSecurityPolicy:
    """Hard limits applied by :func:`parse_secure`.

    There is deliberately no ``allow_dtd`` switch: DTD processing is not
    configurable, it is simply unavailable.
    """

    max_bytes: int = MAX_INPUT_BYTES
    max_depth: int = MAX_ELEMENT_DEPTH
    # No DTD means no entity declarations, so the only permitted depth is 0.
    max_entity_depth: int = 0
    timeout: float = DEFAULT_TIMEOUT


DEFAULT_POLICY = XmlSecurityPolicy()


@dataclass(frozen=True)
class GuardResult:
    """Outcome of a supplemental guard.

    ``allowed`` means the inspected value passes this guard.  The code is
    a stable identifier suitable for logs; ``detail`` only ever contains
    static text, never document or exception content.
    """

    allowed: bool
    code: str
    detail: str = ""


@dataclass(frozen=True)
class ParseOutcome:
    ok: bool
    code: str
    root: ET.Element | None = None


@dataclass(frozen=True)
class SanitizedDocument:
    data: bytes
    removed: bool
    code: str
    allowed: bool


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class XmlSecurityError(Exception):
    code = "XML_INTERNAL"


class DtdForbidden(XmlSecurityError):
    code = "XML_DTD_FORBIDDEN"


class EntityForbidden(XmlSecurityError):
    code = "XML_ENTITY_FORBIDDEN"


class DepthExceeded(XmlSecurityError):
    code = "XML_DEPTH_EXCEEDED"


class ParseTimedOut(XmlSecurityError):
    code = "XML_TIMEOUT"


SAFE_MESSAGES = {
    "XML_OK": "Document accepted.",
    "XML_NOT_TEXT": "Input was not a text document.",
    "XML_TOO_LARGE": "Document exceeds the configured size limit.",
    "XML_DTD_FORBIDDEN": "DTD processing is not allowed.",
    "XML_ENTITY_FORBIDDEN": "Entity declarations are not allowed.",
    "XML_EXTERNAL_ENTITY_FORBIDDEN": "External entities are not allowed.",
    "XML_ENTITY_DEPTH_EXCEEDED": "Entity expansion depth exceeds the limit.",
    "XML_ENTITY_DEPTH_INVALID": "Entity depth limit is invalid.",
    "XML_DEPTH_EXCEEDED": "Document nesting depth exceeds the limit.",
    "XML_TIMEOUT": "Document processing timed out.",
    "XML_SYNTAX": "Document is not well-formed XML.",
    "XML_SCHEMA_INVALID": "Document does not match the schema.",
    "XML_SCHEMA_MISSING": "No schema was supplied for validation.",
    "XML_SCHEMA_OK": "Document matches the schema.",
    "XML_ENCODING_UNSUPPORTED": "Document encoding is not supported.",
    "XML_OOB_BLOCKED": "Out-of-band resolution is disabled.",
    "XML_LOCAL_FILE_DENIED": "Local file access is disabled.",
    "XML_URL_DENIED": "Network URL access is disabled.",
    "XML_FEATURE_DENIED": "Parser feature is not permitted.",
    "XML_FEATURE_ALLOWED": "Parser feature is permitted.",
    "XML_FEATURE_DISABLED": "Parser feature is disabled.",
    "XML_SANITIZED": "Document was sanitized.",
    "XML_INTERNAL": "Request rejected.",
}

_RETRYABLE = frozenset({"XML_TIMEOUT", "XML_TOO_LARGE"})


def _error_code(error: Any) -> str:
    if isinstance(error, XmlSecurityError):
        return error.code
    if isinstance(error, expat.ExpatError):
        return "XML_SYNTAX"
    if isinstance(error, str) and error in SAFE_MESSAGES:
        return error
    return "XML_INTERNAL"


def error_redact(error: Any = None, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
    """Return a client-safe error payload.

    Only a stable code and a canned message are returned.  The original
    exception text is intentionally discarded because parser errors can
    embed document content (and therefore local file contents).
    """

    code = _error_code(error)
    return {
        "code": code,
        "message": SAFE_MESSAGES.get(code, SAFE_MESSAGES["XML_INTERNAL"]),
        "retryable": code in _RETRYABLE,
    }


def fallback(error: Any = None, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
    """Never-raising response used when parsing fails."""

    return {"ok": False, "error": error_redact(error)}


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------

_DOCTYPE_TEXT_RE = re.compile(r"<!DOCTYPE", re.IGNORECASE)
_ENTITY_TEXT_RE = re.compile(r"<!ENTITY\b", re.IGNORECASE)
_EXTERNAL_TEXT_RE = re.compile(r"\b(?:SYSTEM|PUBLIC)\b", re.IGNORECASE)

_UTF8_BOM = b"\xef\xbb\xbf"
_UTF16_BOMS = (b"\xff\xfe", b"\xfe\xff")
_UTF32_BOMS = (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")


def _as_bytes(document: Any) -> bytes | None:
    """Coerce supported document inputs to bytes; never touch the disk."""

    if isinstance(document, bytes):
        return document
    if isinstance(document, (bytearray, memoryview)):
        return bytes(document)
    if isinstance(document, str):
        return document.encode("utf-8", "surrogatepass")
    return None


def _scan_text(raw: bytes) -> str:
    """Best-effort decode used only for cheap pre-screening.

    Falls back to latin-1 so ASCII tokens (``<!DOCTYPE``) are still found
    in documents whose declared encoding is unsupported.  The real parser
    is authoritative.
    """

    if raw.startswith(b"\x00\x00\xfe\xff"):
        return raw[4:].decode("utf-32-be", "replace")
    if raw.startswith(_UTF32_BOMS[0]):
        return raw[4:].decode("utf-32-le", "replace")
    if raw.startswith(_UTF16_BOMS[0]):
        return raw[2:].decode("utf-16-le", "replace")
    if raw.startswith(_UTF16_BOMS[1]):
        return raw[2:].decode("utf-16-be", "replace")
    if raw.startswith(_UTF8_BOM):
        raw = raw[3:]
    # BOM-less UTF-16 still starts with an ASCII '<' interleaved with NUL.
    elif len(raw) >= 2 and raw[0] == 0x3C and raw[1] == 0x00:
        return raw.decode("utf-16-le", "replace")
    elif len(raw) >= 2 and raw[0] == 0x00 and raw[1] == 0x3C:
        return raw.decode("utf-16-be", "replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _decode_utf8(raw: bytes) -> str | None:
    """Strict decode for sanitisation; unsupported encodings fail closed."""

    if raw.startswith(_UTF8_BOM):
        raw = raw[3:]
    elif raw.startswith(_UTF32_BOMS) or raw.startswith(_UTF16_BOMS):
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _coerce_int(value: Any, default: int) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return default
    return default


def _coerce_float(value: Any, default: float) -> float:
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return default
    return default


# ---------------------------------------------------------------------------
# Secure parser
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ElementRule:
    children: frozenset[str] = frozenset()
    attributes: frozenset[str] = frozenset()
    allow_text: bool = True
    min_children: int = 0
    max_children: int | None = None


@dataclass(frozen=True)
class Schema:
    root: str
    rules: Mapping[str, ElementRule]


DEFAULT_SCHEMA = Schema(
    root="document",
    rules={
        "document": ElementRule(children=frozenset({"item"})),
        "item": ElementRule(attributes=frozenset({"id"}), allow_text=True),
    },
)


def _matches_schema(root: ET.Element, schema: Schema) -> bool:
    if root.tag != schema.root:
        return False
    return _element_matches(root, schema)


def _element_matches(elem: ET.Element, schema: Schema) -> bool:
    rule = schema.rules.get(elem.tag)
    if rule is None:
        return False
    if not set(elem.attrib).issubset(rule.attributes):
        return False
    if not rule.allow_text and (elem.text or "").strip():
        return False
    children = list(elem)
    if len(children) < rule.min_children:
        return False
    if rule.max_children is not None and len(children) > rule.max_children:
        return False
    for child in children:
        if child.tag not in rule.children:
            return False
        if not _element_matches(child, schema):
            return False
    return True


def _parse_root(raw: bytes, policy: XmlSecurityPolicy) -> ET.Element:
    """Parse ``raw`` with DOCTYPE/external-entity resolution disabled.

    Raises :class:`XmlSecurityError` subclasses for policy violations and
    ``expat.ExpatError`` for malformed input.
    """

    if policy.timeout <= 0:
        # A non-positive budget means "no parsing time allowed".
        raise ParseTimedOut()

    deadline = time.monotonic() + policy.timeout
    builder = ET.TreeBuilder()
    depth = 0

    def check_time() -> None:
        if time.monotonic() > deadline:
            raise ParseTimedOut()

    def on_start(tag: str, attrs: dict[str, str]) -> None:
        nonlocal depth
        check_time()
        depth += 1
        if depth > policy.max_depth:
            raise DepthExceeded()
        builder.start(tag, attrs)

    def on_end(tag: str) -> None:
        nonlocal depth
        check_time()
        depth -= 1
        builder.end(tag)

    def on_data(data: str) -> None:
        check_time()
        builder.data(data)

    def on_doctype(*_args: Any) -> None:
        # Any DOCTYPE is a hard stop: it is the gateway to entity
        # declarations, external subsets and parameter entities.
        raise DtdForbidden()

    def on_entity(*_args: Any) -> None:
        raise EntityForbidden()

    parser = expat.ParserCreate()
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.StartDoctypeDeclHandler = on_doctype
    parser.EntityDeclHandler = on_entity
    parser.UnparsedEntityDeclHandler = on_entity
    # Returning 0 tells expat "do not resolve"; never called in practice
    # because the DOCTYPE handler fires first.
    parser.ExternalEntityRefHandler = lambda *_args: 0
    parser.StartElementHandler = on_start
    parser.EndElementHandler = on_end
    parser.CharacterDataHandler = on_data

    parser.Parse(raw, True)
    return builder.close()


def parse_secure(
    document: Any,
    policy: XmlSecurityPolicy = DEFAULT_POLICY,
    schema: Schema | None = None,
) -> ParseOutcome:
    """Parse attacker-controlled XML safely.

    Never returns a partially parsed tree on failure and never includes
    document content in the error code.
    """

    raw = _as_bytes(document)
    if raw is None:
        code = "XML_NOT_TEXT"
        audit("xml.parse_error", code)
        return ParseOutcome(False, code)

    if policy.max_bytes < 0 or policy.max_depth < 0:
        audit("xml.parse_error", "XML_INTERNAL")
        return ParseOutcome(False, "XML_INTERNAL")

    if len(raw) > policy.max_bytes:
        audit("xml.parse_error", "XML_TOO_LARGE")
        return ParseOutcome(False, "XML_TOO_LARGE")

    try:
        root = _parse_root(raw, policy)
    except XmlSecurityError as exc:
        audit("xml.parse_error", exc.code)
        return ParseOutcome(False, exc.code)
    except expat.ExpatError:
        audit("xml.parse_error", "XML_SYNTAX")
        return ParseOutcome(False, "XML_SYNTAX")
    except LookupError:
        # Unknown/unsupported encoding declared in the prolog.
        audit("xml.parse_error", "XML_ENCODING_UNSUPPORTED")
        return ParseOutcome(False, "XML_ENCODING_UNSUPPORTED")
    except Exception:  # defensive: never leak internals to the caller
        audit("xml.parse_error", "XML_INTERNAL")
        return ParseOutcome(False, "XML_INTERNAL")

    if schema is not None:
        if not isinstance(schema, Schema):
            audit("xml.parse_error", "XML_INTERNAL")
            return ParseOutcome(False, "XML_INTERNAL")
        if not _matches_schema(root, schema):
            audit("xml.parse_error", "XML_SCHEMA_INVALID")
            return ParseOutcome(False, "XML_SCHEMA_INVALID")

    return ParseOutcome(True, "XML_OK", root)


# ---------------------------------------------------------------------------
# Supplemental guards
# ---------------------------------------------------------------------------

def disable_dtd(source: Any = None, *_args: Any, **_kwargs: Any) -> GuardResult:
    """Reject any document carrying a DOCTYPE/DTD.

    No document means there is nothing to reject; parsing itself still
    fails closed on non-text input.
    """

    raw = _as_bytes(source)
    if raw is None:
        return GuardResult(True, "XML_OK", "no document to inspect")
    if _DOCTYPE_TEXT_RE.search(_scan_text(raw)):
        return GuardResult(False, "XML_DTD_FORBIDDEN")
    return GuardResult(True, "XML_OK")


def external_entity(source: Any = None, *_args: Any, **_kwargs: Any) -> GuardResult:
    """Reject documents that declare or reference external entities."""

    raw = _as_bytes(source)
    if raw is None:
        return GuardResult(True, "XML_OK", "no document to inspect")
    text = _scan_text(raw)
    if not _DOCTYPE_TEXT_RE.search(text):
        return GuardResult(True, "XML_OK")
    if _ENTITY_TEXT_RE.search(text) or _EXTERNAL_TEXT_RE.search(text):
        return GuardResult(False, "XML_EXTERNAL_ENTITY_FORBIDDEN")
    return GuardResult(True, "XML_OK")


def entity_depth(
    value: Any = 0, limit: Any = None, *_args: Any, **_kwargs: Any
) -> GuardResult:
    """Check an entity-expansion nesting depth against the policy limit."""

    depth = _coerce_int(value, DEFAULT_POLICY.max_entity_depth)
    cap = (
        DEFAULT_POLICY.max_entity_depth
        if limit is None
        else _coerce_int(limit, -1)
    )
    if cap < 0:
        return GuardResult(False, "XML_ENTITY_DEPTH_INVALID")
    if depth < 0:
        return GuardResult(False, "XML_ENTITY_DEPTH_INVALID")
    if depth > cap:
        return GuardResult(False, "XML_ENTITY_DEPTH_EXCEEDED")
    return GuardResult(True, "XML_OK")


def schema_validate(
    document: Any = None, schema: Schema | None = None, *_args: Any, **_kwargs: Any
) -> GuardResult:
    """Parse the document safely and validate it against ``schema``.

    Validation without a schema is a misconfiguration and fails closed.
    """

    if not isinstance(schema, Schema):
        return GuardResult(False, "XML_SCHEMA_MISSING")
    outcome = parse_secure(document, schema=schema)
    return GuardResult(outcome.ok, outcome.code)


def parser_feature(
    parser: Any = None, feature: Any = None, value: Any = None, *_args: Any,
    **_kwargs: Any,
) -> GuardResult:
    """Decide whether a parser feature may be enabled.

    Unknown features are denied (fail closed).  Features that enable DTD
    or external-entity processing are never permitted.
    """

    name = feature if isinstance(feature, str) else None
    if name is None and isinstance(parser, str):
        name = parser
    if name is None:
        return GuardResult(False, "XML_FEATURE_DENIED", "feature not specified")

    normalized = name.strip().lower().replace("-", "_")
    if normalized in _DANGEROUS_FEATURES:
        if value is False:
            return GuardResult(True, "XML_FEATURE_DISABLED")
        return GuardResult(False, "XML_FEATURE_DENIED")
    if normalized in _SAFE_FEATURES:
        return GuardResult(True, "XML_FEATURE_ALLOWED")
    return GuardResult(False, "XML_FEATURE_DENIED")


_DANGEROUS_FEATURES = frozenset(
    {
        "dtd",
        "doctype",
        "load_dtd",
        "load_external_dtd",
        "dtd_validation",
        "validate",
        "resolve_entities",
        "external_general_entities",
        "external_parameter_entities",
        "parameter_entity_parsing",
        "external_entity_ref",
        "unparsed_entity_decl",
        "entity_decl",
        "use_foreign_dtd",
        "network",
        "url",
        "file",
        "file_access",
        "local_file",
        "oob",
    }
)

_SAFE_FEATURES = frozenset(
    {
        "namespace",
        "namespace_prefixes",
        "coalesce",
        "characters",
        "tag_name",
        "utf8",
    }
)


def oob_block(target: Any = None, *_args: Any, **_kwargs: Any) -> GuardResult:
    """Out-of-band resolution is never allowed, whatever the target."""

    return GuardResult(False, "XML_OOB_BLOCKED")


def local_file_deny(target: Any = None, *_args: Any, **_kwargs: Any) -> GuardResult:
    """Local file access is never allowed, whatever the target."""

    return GuardResult(False, "XML_LOCAL_FILE_DENIED")


def url_deny(target: Any = None, *_args: Any, **_kwargs: Any) -> GuardResult:
    """Remote URL access is never allowed, whatever the target."""

    return GuardResult(False, "XML_URL_DENIED")


def size_limit(
    value: Any = None, limit: Any = None, *_args: Any, **_kwargs: Any
) -> GuardResult:
    """Check a document's byte size against the configured limit."""

    raw = _as_bytes(value)
    size = len(raw) if raw is not None else 0
    cap = (
        DEFAULT_POLICY.max_bytes
        if limit is None
        else _coerce_int(limit, -1)
    )
    if cap < 0:
        return GuardResult(False, "XML_INTERNAL", "invalid size limit")
    if size > cap:
        return GuardResult(False, "XML_TOO_LARGE")
    return GuardResult(True, "XML_OK")


def timeout(
    elapsed: Any = None, limit: Any = None, *_args: Any, **_kwargs: Any
) -> GuardResult:
    """Check parse time spent against the configured timeout."""

    used = _coerce_float(elapsed, 0.0)
    cap = (
        DEFAULT_POLICY.timeout
        if limit is None
        else _coerce_float(limit, -1.0)
    )
    if cap < 0 or used < 0:
        return GuardResult(False, "XML_INTERNAL", "invalid timeout")
    if used > cap:
        return GuardResult(False, "XML_TIMEOUT")
    return GuardResult(True, "XML_OK")


def validation(
    document: Any = None, schema: Schema | None = None, *_args: Any, **_kwargs: Any
) -> ParseOutcome:
    """Full pipeline: secure parse, then schema validation if supplied."""

    if schema is None:
        return parse_secure(document)
    if not isinstance(schema, Schema):
        return ParseOutcome(False, "XML_INTERNAL")
    return parse_secure(document, schema=schema)


# ---------------------------------------------------------------------------
# Sanitisation
# ---------------------------------------------------------------------------

def _doctype_end(text: str, start: int) -> int | None:
    """Return the index just past the DOCTYPE starting at ``start``."""

    depth = 0
    quote: str | None = None
    k = start
    n = len(text)
    while k < n:
        if quote is not None:
            if text[k] == quote:
                quote = None
            k += 1
            continue
        if text.startswith("<!--", k):
            end = text.find("-->", k + 4)
            if end < 0:
                return None
            k = end + 3
            continue
        if text.startswith("<?", k):
            end = text.find("?>", k + 2)
            if end < 0:
                return None
            k = end + 2
            continue
        ch = text[k]
        if ch in "\"'":
            quote = ch
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth < 0:
                return None
        elif ch == ">" and depth == 0:
            return k + 1
        k += 1
    return None


def _strip_doctype(text: str) -> tuple[str | None, bool]:
    """Remove DOCTYPE declarations (including internal subsets).

    Comments and CDATA sections are copied verbatim so a doctype-looking
    string inside them is not touched.  Returns ``(None, False)`` for
    unterminated constructs so the caller can fail closed.
    """

    out: list[str] = []
    removed = False
    i = 0
    n = len(text)
    chunk_start = 0
    while i < n:
        if text[i] != "<":
            i += 1
            continue
        match = _DOCTYPE_TEXT_RE.match(text, i)
        if match:
            out.append(text[chunk_start:i])
            end = _doctype_end(text, match.end())
            if end is None:
                return None, False
            removed = True
            i = chunk_start = end
            continue
        if text.startswith("<!--", i):
            end = text.find("-->", i + 4)
            if end < 0:
                return None, False
            i = end + 3
            continue
        if text.startswith("<![CDATA[", i):
            end = text.find("]]>", i + 9)
            if end < 0:
                return None, False
            i = end + 3
            continue
        i += 1
    out.append(text[chunk_start:])
    return "".join(out), removed


def sanitize(document: Any = None, *_args: Any, **_kwargs: Any) -> SanitizedDocument:
    """Strip DOCTYPE declarations from a document, failing closed.

    The sanitised bytes are re-parsed with :func:`parse_secure`; if the
    result still cannot be parsed (for example because the body references
    an entity that no longer exists) the sanitised document is returned
    with ``allowed=False``.
    """

    raw = _as_bytes(document)
    if raw is None:
        return SanitizedDocument(b"", False, "XML_NOT_TEXT", False)

    text = _decode_utf8(raw)
    if text is None:
        return SanitizedDocument(b"", False, "XML_ENCODING_UNSUPPORTED", False)

    cleaned, removed = _strip_doctype(text)
    if cleaned is None:
        return SanitizedDocument(b"", False, "XML_SYNTAX", False)

    data = cleaned.encode("utf-8")
    outcome = parse_secure(data)
    if not outcome.ok:
        return SanitizedDocument(data, removed, outcome.code, False)
    if removed:
        return SanitizedDocument(data, True, "XML_SANITIZED", True)
    return SanitizedDocument(data, False, "XML_OK", True)


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------

AUDIT_LOG: deque[dict[str, Any]] = deque(maxlen=256)


def _safe_label(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, BaseException):
        return _error_code(value)
    if isinstance(value, (str, int, float, bool)):
        return str(value)[:64]
    return f"<{type(value).__name__}>"


def audit(event: Any = None, code: Any = None, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
    """Record a content-free audit event and return the record.

    Only labels, codes and a timestamp are stored; document bytes and
    exception messages are never placed in the audit log.
    """

    record = {
        "ts": time.time(),
        "event": _safe_label(event),
        "code": _error_code(code) if isinstance(code, BaseException) else _safe_label(code),
    }
    AUDIT_LOG.append(record)
    return record
