"""Development static host and same-origin proxy for the Delta-NIDS dashboard."""
from pathlib import Path
import json
import os
import urllib.error
import urllib.request
import time

from flask import Flask, jsonify, render_template, request, Response
from datetime import datetime
from zoneinfo import ZoneInfo
from sqlalchemy.exc import DBAPIError

from core.detection_engine import DetectionEngine
from core.rule_management import (RuleValidationError, generate_rule_text, parse_rule_text,
                                  port_variables, validate_rule)
from database.models import Rule, init_db

ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ROOT.parent
app = Flask(__name__, static_folder=str(ROOT / "static"), template_folder=str(ROOT / "templates"))
API_URL = os.environ.get("DELTA_NIDS_API_URL", "http://127.0.0.1:8080").rstrip("/")
DB_PATH = os.environ.get("DELTA_NIDS_DB_PATH", str(PROJECT_ROOT / "database" / "nids.db"))


@app.errorhandler(DBAPIError)
def _database_busy(error):
    """Report transient database contention instead of a stack-trace 500.

    WAL mode plus busy timeouts make lock collisions rare; if one still
    surfaces (for example during a heavy export), the client can simply
    retry, so report it as service unavailable.
    """
    return jsonify({"error": "database is busy; retry shortly"}), 503


def _rule_payload(rule: Rule) -> dict:
    """Authoritative rule metadata assembled from the persisted row and its rule_json.

    Only fields actually present on the loaded rule are returned; missing
    metadata is never fabricated.
    """
    try:
        value = json.loads(rule.rule_json) if rule.rule_json else {}
    except json.JSONDecodeError:
        value = {}
    if not isinstance(value, dict):
        value = {}
    value.update({
        "gid": rule.gid, "sid": rule.sid, "revision": rule.revision,
        "message": rule.message or value.get("message", ""), "enabled": bool(rule.enabled),
        "source_file": rule.source_file or "", "protocol": rule.protocol or value.get("protocol", ""),
        "priority": rule.priority, "category": rule.category or value.get("category", ""),
        "rule_text": rule.rule_text or value.get("rule_text", ""),
        "source": rule.source_file or value.get("source", ""),
        "updated_at": rule.updated_at,
    })
    # Expose every supported rule field (with None when absent) so the Rules
    # tab can render the complete rule contract without inventing values.
    for key in ("action", "direction", "src_ip", "dst_ip", "src_port", "dst_port",
                "content", "pcre", "regex", "nocase", "severity", "classification",
                "service", "buffer", "offset", "depth", "distance", "within",
                "threshold", "suppression_key"):
        value.setdefault(key, None)
    return value


def _validate_and_compile(payload):
    if isinstance(payload, str):
        rule = parse_rule_text(payload)
    elif isinstance(payload, dict):
        rule = validate_rule(payload)
    else:
        raise ValueError("request must contain a rule string or JSON object")
    compiled = DetectionEngine._compile_rules([rule])
    if not compiled or compiled[0]["unsupported"]:
        unsupported = sorted(compiled[0]["unsupported"]) if compiled else ["rule"]
        raise ValueError(f"rule is not executable: {', '.join(unsupported)}")
    # The Python matcher supports protocol-only rules only for ICMP/ARP (and
    # ICMPv6). A protocol-only TCP/UDP/IP rule would be accepted into storage
    # but can never match because passive payload inspection needs content or
    # a regex.
    if not rule.get("content") and not rule.get("pcre") and not rule.get("regex") and rule.get("protocol") not in {"ICMP", "ICMPV6", "ARP"}:
        raise ValueError("rule requires content or pcre/regex; protocol-only rules are supported only for ICMP, ICMPv6, or ARP")
    rule.setdefault("rule_text", payload if isinstance(payload, str) else "")
    return rule


def _error_response(error: Exception) -> tuple:
    """Render structured rule failures as a user-facing validation message."""
    if isinstance(error, RuleValidationError):
        return jsonify({"error": error.format()}), 400
    return jsonify({"error": str(error)}), 400


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/rules")
def list_rules():
    """Return authoritative rule state and search all stored rule metadata."""
    try:
        page = max(1, int(request.args.get("page", "1")))
        page_size = min(500, max(1, int(request.args.get("page_size", "50"))))
    except ValueError:
        return jsonify({"error": "page and page_size must be positive integers"}), 400
    search = request.args.get("search", "").strip().casefold()
    session = init_db(DB_PATH)
    try:
        rows = session.query(Rule).order_by(Rule.sid, Rule.revision).all()
        if search:
            rows = [row for row in rows if search in " ".join(str(value or "") for value in (
                row.gid, row.sid, row.revision, row.message, row.protocol, row.source_file,
                row.category, row.rule_text, row.rule_json, row.enabled,
            )).casefold()]
        total = len(rows)
        start = (page - 1) * page_size
        return jsonify({"items": [_rule_payload(row) for row in rows[start:start + page_size]],
                       "page": page, "page_size": page_size, "total": total})
    finally:
        session.close()


@app.get("/api/rules/<int:sid>/<int:revision>")
def get_rule(sid: int, revision: int):
    """Return the full persisted metadata for one loaded rule."""
    try:
        session = init_db(DB_PATH)
        try:
            row = session.query(Rule).filter_by(sid=sid, revision=revision).one_or_none()
            if row is None:
                return jsonify({"error": "rule not found"}), 404
            return jsonify(_rule_payload(row))
        finally:
            session.close()
    except OSError as error:
        return jsonify({"error": str(error)}), 400


@app.post("/api/rules/validate")
def validate_rule_endpoint():
    """Validate a rule (text, fields, or JSON) without persisting it."""
    body = request.get_json(silent=True) or {}
    try:
        payload = body.get("rule", body)
        if isinstance(payload, dict) and "fields" in payload:
            text = generate_rule_text(payload["fields"])
            rule = parse_rule_text(text)
        else:
            rule = _validate_and_compile(payload)
        return jsonify({"valid": True, "rule": rule,
                        "rule_text": rule.get("rule_text", "")})
    except (ValueError, TypeError) as error:
        if isinstance(error, RuleValidationError):
            return jsonify({"valid": False, "error": error.format()}), 400
        return jsonify({"valid": False, "error": str(error)}), 400


@app.get("/api/port-variables")
def list_port_variables():
    """Expose the centrally configured port groups for the rule editor."""
    return jsonify({"variables": port_variables()})


@app.post("/api/rules")
def add_rule():
    body = request.get_json(silent=True) or {}
    try:
        payload = body.get("rule", body)
        if isinstance(payload, dict) and "fields" in payload:
            text = generate_rule_text(payload["fields"])
            rule = parse_rule_text(text)
        else:
            rule = _validate_and_compile(payload)
        session = init_db(DB_PATH)
        try:
            existing = session.query(Rule).filter_by(
                gid=int(rule["gid"]), sid=int(rule["sid"]), revision=int(rule["rev"])
            ).one_or_none()
            if existing is not None:
                return jsonify({"error": "a rule with this gid/sid/revision already exists"}), 409
            row = Rule(
                gid=int(rule["gid"]), sid=int(rule["sid"]), revision=int(rule["rev"]),
                message=rule.get("message", ""), enabled=True, source_file="runtime",
                priority=int(rule.get("priority", 3) or 3), protocol=rule.get("protocol", ""),
                category=rule.get("category", rule.get("classification", "")),
                rule_text=rule.get("rule_text", ""),
                rule_json=json.dumps({**rule, "enabled": True}, separators=(",", ":")),
                updated_at=time_ns(),
            )
            session.add(row)
            session.commit()
            return jsonify(_rule_payload(row)), 201
        finally:
            session.close()
    except (ValueError, TypeError, OSError) as error:
        return _error_response(error)


def time_ns() -> int:
    return time.time_ns()


@app.patch("/api/rules/<int:sid>/<int:revision>")
def update_rule(sid: int, revision: int):
    body = request.get_json(silent=True) or {}
    try:
        session = init_db(DB_PATH)
        try:
            query = session.query(Rule).filter_by(sid=sid, revision=revision)
            row = query.one_or_none()
            if row is None:
                return jsonify({"error": "rule not found"}), 404
            if "enabled" not in body or not isinstance(body["enabled"], bool):
                return jsonify({"error": "enabled must be a boolean"}), 400
            row.enabled = body["enabled"]
            if row.rule_json:
                try:
                    value = json.loads(row.rule_json)
                except json.JSONDecodeError:
                    value = {}
                value["enabled"] = row.enabled
                row.rule_json = json.dumps(value, separators=(",", ":"))
            row.updated_at = time_ns()
            session.commit()
            return jsonify(_rule_payload(row))
        finally:
            session.close()
    except (OSError, ValueError) as error:
        return jsonify({"error": str(error)}), 400


@app.delete("/api/rules/<int:sid>/<int:revision>")
def delete_rule(sid: int, revision: int):
    try:
        session = init_db(DB_PATH)
        try:
            row = session.query(Rule).filter_by(sid=sid, revision=revision).one_or_none()
            if row is None:
                return jsonify({"error": "rule not found"}), 404
            session.delete(row)
            session.commit()
            return jsonify({"deleted": True, "gid": row.gid, "sid": sid, "revision": revision})
        finally:
            session.close()
    except OSError as error:
        return jsonify({"error": str(error)}), 400


@app.route("/api/<path:path>", methods=["GET", "DELETE"])
def proxy_api(path):
    url = f"{API_URL}/api/{path}"
    if request.query_string:
        url += "?" + request.query_string.decode("utf-8")
    try:
        upstream = urllib.request.Request(url, method=request.method, headers={"Accept": "application/json"})
        with urllib.request.urlopen(upstream, timeout=10) as response:
            payload = response.read()
            headers = {"Content-Type": response.headers.get_content_type()}
            if path in {"alerts/export", "traffic/export"}:
                kind = "alerts" if path == "alerts/export" else "traffic"
                date = datetime.now(ZoneInfo("Asia/Kolkata")).date().isoformat()
                headers["Content-Disposition"] = f'attachment; filename="delta-nids-{kind}-{date}.json"'
            return Response(payload, status=response.status, headers=headers)
    except urllib.error.HTTPError as error:
        return Response(error.read() or b'{"error":"upstream API error"}', status=error.code, content_type="application/json")
    except (urllib.error.URLError, OSError):
        return Response(b'{"error":"Delta-NIDS API unavailable"}', status=502, content_type="application/json")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("DELTA_NIDS_DASHBOARD_PORT", "8081")), debug=False, use_reloader=False)
