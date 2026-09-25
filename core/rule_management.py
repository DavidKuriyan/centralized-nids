"""Canonical passive rule parser for Delta-NIDS.

This module is the single rule compiler for the dashboard, API, file loading,
and runtime refresh paths. All accepted rule text is normalized here into a
canonical JSON rule that the Python detection engine (and, for the supported
canonical subset, the native loader) can compile deterministically.

Supported destination/source port syntax (any mix, comma separated):

    80              single port
    80,443          port list
    [80,443]        bracketed port list
    1:1024          port range
    $HTTP_PORTS     pre-defined port variable
    $HTTP_PORTS,$HTTPS_PORTS   multiple variables

Unknown variables produce a user-facing validation error instead of a
low-level "invalid port" message.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

_ACTIONS = {"ALERT", "LOG"}
_PROTOCOLS = {"TCP", "UDP", "ICMP", "ICMPV6", "ARP", "IP"}

# Centrally configurable pre-defined port groups. Override any entry with a
# JSON file `rules/port_variables.json` of the form
# {"HTTP_PORTS": [80, 8080, ...], ...} or the DELTA_NIDS_PORT_VARIABLES
# environment variable containing the same JSON object. Environment values are
# merged on top of the file, which is merged on top of these defaults.
DEFAULT_PORT_VARIABLES: dict[str, list[int]] = {
    "HTTP_PORTS": [80, 8080, 8000, 8008, 8888],
    "HTTPS_PORTS": [443, 8443],
    "DNS_PORTS": [53],
    "SSH_PORTS": [22],
    "FTP_PORTS": [20, 21],
    "SMTP_PORTS": [25],
    "DATABASE_PORTS": [1433, 1521, 3306, 5432],
}

_PORT_VARIABLES: dict[str, list[int]] = dict(DEFAULT_PORT_VARIABLES)
_VARIABLE_SOURCES: list[str] = ["built-in defaults"]


class RuleValidationError(ValueError):
    """Structured rule validation failure with a user-facing message.

    Attributes:
        field: the rule section that failed (e.g. "Destination Port").
        problem: a human description of the failure.
        expected: optional list of accepted forms (rendered under "Expected:").
    """

    def __init__(self, field: str, problem: str, expected: list[str] | None = None):
        super().__init__(problem)
        self.field = field
        self.problem = problem
        self.expected = expected

    def format(self) -> str:
        if self.expected:
            block = "\n".join(self.expected)
            return (f"Rule validation failed\n\nField:\n{self.field}\n\n"
                    f"Problem:\n{self.problem}\n\nExpected:\n{block}")
        return f"Rule validation failed\n\nField:\n{self.field}\n\nProblem:\n{self.problem}"


def _port_expression_error(field: str) -> RuleValidationError:
    return RuleValidationError(
        field,
        "Unknown or unsupported port expression.",
        ["80", "80,443", "[80,443]", "1:1024", "$HTTP_PORTS"],
    )


def _unknown_variable_error(name: str) -> RuleValidationError:
    available = ", ".join(f"${key}" for key in sorted(_PORT_VARIABLES))
    return RuleValidationError(
        "Port variable",
        f"Unknown port variable '${name}'. Available variables: {available}.",
    )


def port_variables() -> dict[str, list[int]]:
    """Return the currently configured port variable table."""
    return {key: list(value) for key, value in _PORT_VARIABLES.items()}


def load_port_variables(path: str | None = None) -> dict[str, list[int]]:
    """(Re)load the port variable table from defaults, an optional JSON file,
    and the DELTA_NIDS_PORT_VARIABLES environment variable (in that order).

    Returns the active table. File/environment entries with unknown variable
    names are added to the table; the load never removes built-in groups.
    """
    table = {key: list(value) for key, value in DEFAULT_PORT_VARIABLES.items()}
    merged: dict[str, list[int]] = dict(table)
    sources: list[str] = ["built-in defaults"]

    def merge(payload: Any, label: str) -> None:
        nonlocal merged
        if not isinstance(payload, dict):
            return
        for key, value in payload.items():
            if isinstance(value, (list, tuple)) and all(
                isinstance(port, int) and 0 <= port <= 65535 for port in value
            ):
                merged[str(key).upper()] = [int(port) for port in value]
                if label not in sources:
                    sources.append(label)

    if path and os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as stream:
                merge(json.load(stream), f"file {path}")
        except (OSError, json.JSONDecodeError):
            pass
    env = os.environ.get("DELTA_NIDS_PORT_VARIABLES")
    if env:
        try:
            merge(json.loads(env), "DELTA_NIDS_PORT_VARIABLES")
        except (json.JSONDecodeError, TypeError):
            pass
    _PORT_VARIABLES.clear()
    _PORT_VARIABLES.update(merged)
    if "" not in _VARIABLE_SOURCES:
        _VARIABLE_SOURCES[:] = [s for s in sources]
    return port_variables()


def set_port_variables(table: dict[str, list[int]]) -> None:
    """Replace the active variable table (used by tests and runtime config)."""
    _PORT_VARIABLES.clear()
    _PORT_VARIABLES.update({str(key).upper(): [int(p) for p in value]
                            for key, value in (table or {}).items()})
    _VARIABLE_SOURCES[:] = ["configured"]


def _expand_variable_token(token: str, field: str) -> list[int]:
    name = token[1:].upper()
    ports = _PORT_VARIABLES.get(name)
    if ports is None:
        raise _unknown_variable_error(name)
    return [int(port) for port in ports]


_TOKEN_RE = re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$")


def parse_port_expression(text: Any, field: str = "Destination Port") -> Any:
    """Parse a user-facing port expression into the canonical form.

    Canonical output is either an int (a single port) or a sorted
    comma-separated string of ports and ranges (e.g. "80,443", "1:1024",
    "20:21,53,1000:1024"). 'any' is preserved as the wildcard sentinel.
    """
    if text is None:
        return None
    if isinstance(text, int):
        if not 0 <= text <= 65535:
            raise RuleValidationError(field, f"port {text} is out of range 0-65535.")
        return text
    if isinstance(text, list):
        ports = []
        for entry in text:
            if isinstance(entry, int) and 0 <= entry <= 65535:
                ports.append(entry)
            elif isinstance(entry, str):
                ports.extend(_parse_port_tokens(entry, field))
            else:
                raise _port_expression_error(field)
        if not ports:
            raise _port_expression_error(field)
        return _canonical_port_set(ports)
    raw = str(text).strip()
    if not raw:
        return None
    if raw.lower() == "any":
        return "any"
    ports = _parse_port_tokens(raw, field)
    if not ports:
        raise _port_expression_error(field)
    return _canonical_port_set(ports)


def _parse_port_tokens(raw: str, field: str) -> list[int]:
    """Expand a comma-separated expression into an explicit port list."""
    text = raw
    # Accept both [80,443] and 80,443 (brackets are purely cosmetic).
    if len(text) >= 2 and text[0] == "[" and text[-1] == "]":
        text = text[1:-1]
    ports: list[int] = []
    for token in text.split(","):
        token = token.strip()
        if not token:
            continue
        if token.startswith("$"):
            if not _TOKEN_RE.match(token):
                raise RuleValidationError(
                    field,
                    f"Malformed port variable '{token}'. Port variables look like '$HTTP_PORTS'.",
                    ["$HTTP_PORTS", "$HTTPS_PORTS", "$DNS_PORTS"],
                )
            ports.extend(_expand_variable_token(token, field))
            continue
        if re.fullmatch(r"\d+", token):
            value = int(token)
            if value > 65535:
                raise RuleValidationError(field, f"port {value} is out of range 0-65535.")
            ports.append(value)
            continue
        range_match = re.fullmatch(r"(\d*):(\d*)", token)
        if range_match:
            low_text, high_text = range_match.groups()
            low = int(low_text) if low_text else 0
            high = int(high_text) if high_text else 65535
            if low > high or high > 65535:
                raise RuleValidationError(field, f"invalid port range '{token}'.")
            ports.extend(range(low, high + 1))
            continue
        raise _port_expression_error(field)
    return ports


def _canonical_port_set(ports: list[int]) -> Any:
    """Collapse explicit ports into the canonical representation.

    A single port becomes an int. Otherwise overlapping/adjacent values are
    merged and rendered as sorted comma-separated ranges: [80,443] -> "80,443",
    [20,21] -> "20:21", [1..1024] -> "1:1024".
    """
    ordered = sorted(set(ports))
    if not ordered:
        raise ValueError("empty port set")
    if len(ordered) == 1:
        return ordered[0]
    ranges: list[tuple[int, int]] = []
    start = previous = ordered[0]
    for port in ordered[1:]:
        if port == previous + 1:
            previous = port
            continue
        ranges.append((start, previous))
        start = previous = port
    ranges.append((start, previous))
    tokens = [str(low) if low == high else f"{low}:{high}" for low, high in ranges]
    return ",".join(tokens)


# Hex content escapes: content:"User-Agent|3a| Nmap" means the byte
# sequence 0x3a (':') between literal text. |3a 20| is a space-separated byte
# list. |3a| Nmap decodes to "User-Agent: Nmap".
_HEX_TOKEN = re.compile(r"\|([0-9A-Fa-f][0-9A-Fa-f](?:[ \t]+[0-9A-Fa-f][0-9A-Fa-f])*)\|")


def decode_content(value: Any) -> bytes:
    """Convert a content spec (str or list[str]) into matching bytes.

    Literal text is kept as-is; |HH| sequences decode to raw bytes. This makes
    rules such as `content:"User-Agent|3a| Nmap"` match the wire payload
    "User-Agent: Nmap".
    """
    if isinstance(value, bytes):
        return value
    if isinstance(value, list):
        return b"".join(decode_content(entry) for entry in value)
    text = str(value or "")
    output = bytearray()
    position = 0
    for match in _HEX_TOKEN.finditer(text):
        output.extend(text[position:match.start()].encode("utf-8", errors="ignore"))
        for token in match.group(1).split():
            output.append(int(token, 16))
        position = match.end()
    output.extend(text[position:].encode("utf-8", errors="ignore"))
    return bytes(output)


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value[1:-1]
    return value


def _validate_network(address: str, label: str) -> None:
    if address.lower() == "any":
        return
    try:
        import ipaddress
        if "/" in address:
            ipaddress.ip_network(address, strict=False)
        else:
            ipaddress.ip_address(address)
    except ValueError as error:
        raise RuleValidationError(label, f"invalid {label.lower()} network: {address}",
                                  ["any", "192.168.68.110", "192.168.68.0/24"]) from error


def _options(text: str) -> dict[str, str]:
    """Split rule options on unquoted semicolons."""
    values: dict[str, str] = {}
    parts: list[str] = []
    start = 0
    quoted = False
    escaped = False
    for index, character in enumerate(text):
        if escaped:
            escaped = False
        elif character == "\\" and quoted:
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif character == ";" and not quoted:
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    for part in parts:
        if ":" not in part:
            key = part.strip().lower()
            if key:
                values[key] = ""
            continue
        key, value = part.split(":", 1)
        key = key.strip().lower()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", key):
            values[key] = _unquote(value)
    return values


def parse_rule_text(rule_text: str) -> dict[str, Any]:
    """Parse the supported passive subset of signature rule syntax."""
    load_port_variables()
    text = str(rule_text or "").strip()
    match = re.match(
        r"^(\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s+(->|<>|<-)\s+(\S+)\s+(\S+)\s*\((.*)\)\s*$",
        text, re.IGNORECASE,
    )
    if not match:
        raise ValueError("expected '<action> <protocol> <src> <src_port> -> <dst> <dst_port> (options)'")
    action, protocol, source, source_port, direction, destination, destination_port, options_text = match.groups()
    action = action.upper()
    protocol = protocol.upper()
    if action not in _ACTIONS:
        raise ValueError("only ALERT and LOG actions are supported in passive mode")
    if protocol not in _PROTOCOLS:
        raise ValueError(f"unsupported protocol: {protocol}")
    _validate_network(source, "Source IP")
    _validate_network(destination, "Destination IP")

    options = _options(options_text)
    if "sid" not in options:
        raise ValueError("rule requires a sid option")
    try:
        sid = int(options["sid"])
        revision = int(options.get("rev", "1"))
        gid = int(options.get("gid", "1"))
    except ValueError as error:
        raise ValueError("sid, gid, and rev must be integers") from error
    if min(sid, revision, gid) <= 0:
        raise ValueError("sid, gid, and rev must be positive")

    src_network = None if source.lower() == "any" else source
    dst_network = None if destination.lower() == "any" else destination
    result: dict[str, Any] = {
        "gid": gid, "sid": sid, "rev": revision, "action": action, "protocol": protocol,
        "src_ip": src_network, "dst_ip": dst_network,
        "src_port": parse_port_expression(source_port, "Source Port"),
        "dst_port": parse_port_expression(destination_port, "Destination Port"),
        "direction": "any" if direction == "<>" else ("server_to_client" if direction == "<-" else "client_to_server"),
        "message": options.get("msg", f"Delta-NIDS rule {sid}"),
        "rule_text": text, "enabled": True,
    }
    if "content" in options:
        content = options["content"]
        decode_content(content)  # validate hex syntax early for a clear error
        result["content"] = content
    if "pcre" in options:
        result["pcre"] = options["pcre"]
    if "regex" in options:
        result["regex"] = options["regex"]
    if "nocase" in options:
        result["nocase"] = True
    if "priority" in options:
        try:
            result["priority"] = int(options["priority"])
        except ValueError as error:
            raise ValueError("priority must be an integer") from error
    if "classtype" in options:
        result["category"] = options["classtype"]
    if "severity" in options:
        result["severity"] = options["severity"].upper()
    # Reject unknown options so a typo cannot silently disable matching.
    known = {"msg", "sid", "gid", "rev", "content", "pcre", "regex", "nocase", "priority",
             "classtype", "severity", "threshold", "suppression_key", "flow"}
    unknown = sorted(set(options).difference(known))
    if "threshold" in options:
        try:
            value = json.loads(options["threshold"]) if options["threshold"].strip().startswith("{") else None
            if isinstance(value, dict):
                result["threshold"] = value
        except json.JSONDecodeError:
            pass
    if unknown:
        raise RuleValidationError(
            "Rule options",
            f"unsupported rule options: {', '.join(unknown)}",
        )
    return validate_rule(result)


def validate_rule(value: Any) -> dict[str, Any]:
    """Validate and normalize a rule dict (JSON rules, UI rules, API rules)."""
    load_port_variables()
    if not isinstance(value, dict):
        raise ValueError("rule must be a JSON object")
    rule = dict(value)
    try:
        rule["gid"] = int(rule.get("gid", 1))
        rule["sid"] = int(rule["sid"])
        rule["rev"] = int(rule.get("rev", rule.get("revision", 1)))
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("rule requires positive integer sid and rev") from error
    if min(rule["gid"], rule["sid"], rule["rev"]) <= 0:
        raise ValueError("gid, sid, and rev must be positive")
    action = str(rule.get("action", "ALERT")).upper()
    if action not in _ACTIONS:
        raise ValueError("only ALERT and LOG actions are supported in passive mode")
    rule["action"] = action
    protocol = str(rule.get("protocol", "IP")).strip().upper()
    if protocol not in _PROTOCOLS:
        raise ValueError(f"unsupported protocol: {protocol}")
    rule["protocol"] = protocol
    rule["message"] = str(rule.get("message", f"Delta-NIDS rule {rule['sid']}"))[:512]
    rule["enabled"] = bool(rule.get("enabled", True))
    for field in ("src_port", "dst_port"):
        if field in rule and rule[field] is not None:
            label = "Source Port" if field == "src_port" else "Destination Port"
            rule[field] = parse_port_expression(rule[field], label)
    if "content" in rule:
        if not isinstance(rule["content"], (str, list)):
            raise ValueError("content must be a string or string array")
        if isinstance(rule["content"], list) and not all(isinstance(item, str) for item in rule["content"]):
            raise ValueError("content list entries must be strings")
        decode_content(rule["content"])  # surface hex-syntax errors up front
    if "pcre" in rule or "regex" in rule:
        try:
            re.compile(str(rule.get("pcre") or rule.get("regex")), re.I if rule.get("nocase") else 0)
        except re.error as error:
            raise ValueError(f"invalid regular expression: {error}") from error
    allowed = {
        "gid", "sid", "rev", "revision", "action", "protocol", "src_ip", "dst_ip",
        "src_port", "dst_port", "message",
        "severity", "priority", "content", "pcre", "regex", "nocase", "direction", "service",
        "buffer", "classification", "category", "offset", "depth", "distance", "within", "threshold",
        "suppression_key", "rule_text", "enabled",
    }
    unsupported = sorted(set(rule).difference(allowed))
    if unsupported:
        raise ValueError(f"unsupported rule fields: {', '.join(unsupported)}")
    return rule


def generate_rule_text(fields: dict[str, Any]) -> str:
    """Build canonical rule text from structured editor fields.

    Accepts keys: action, protocol, src_ip, src_port, direction, dst_ip,
    dst_port, message, content, sid, rev, priority, severity, nocase.
    Port expressions may be the friendly forms (int, list, range, variable).
    """
    action = str(fields.get("action", "alert")).upper()
    protocol = str(fields.get("protocol", "tcp")).upper()
    src_ip = str(fields.get("src_ip") or "any")
    dst_ip = str(fields.get("dst_ip") or "any")
    src_port = parse_port_expression(fields.get("src_port") or "any", "Source Port")
    dst_port = parse_port_expression(fields.get("dst_port") or "any", "Destination Port")
    direction = fields.get("direction") or "->"
    default_message = f"Delta-NIDS rule {fields.get('sid', 0)}"
    message = fields.get("message") or default_message
    options = [f"msg:\"{message}\""]
    if fields.get("content"):
        options.append(f"content:\"{fields['content']}\"")
    if fields.get("nocase"):
        options.append("nocase")
    if fields.get("pcre"):
        options.append(f"pcre:\"{fields['pcre']}\"")
    if fields.get("priority") is not None:
        options.append(f"priority:{fields['priority']}")
    if fields.get("severity"):
        options.append(f"severity:{str(fields['severity']).upper()}")
    options.append(f"sid:{fields.get('sid', 0)}")
    options.append(f"rev:{fields.get('rev', fields.get('revision', 1))}")
    text = (f"{action} {protocol} {src_ip} {src_port} {direction} "
            f"{dst_ip} {dst_port} ({'; '.join(options)};)")
    parse_rule_text(text)  # validate before returning
    return text