"""Offline predicates. Scanner detections are always advisory."""
import ipaddress
import re
from xml.etree import ElementTree

from .common import SHA, Invalid, MAX_DOCUMENT, digest, fields, identifier, integer, require, strict_json
from .traffic import endpoint, traffic_samples

SIGNALS = {"semgrep", "trivy", "zap", "slither", "testssl", "echidna", "forge"}
RULES = {"http.private_json", "http.nosniff", "tcp.exposure", "postgres.superuser"} | SIGNALS


def validate_rule(rule, target, control):
    require(isinstance(rule, dict) and isinstance(rule.get("kind"), str) and rule["kind"] in RULES, "unknown rule")
    kind = rule["kind"]
    if kind.startswith("http."):
        if kind == "http.nosniff":
            fields(rule, ("kind", "finding_id", "media_type"))
            require(rule["media_type"] in ("text/html", "application/json", "text/javascript", "text/css"),
                    "unsupported media type")
        else:
            keys = ("owner_subject_sha256", "peer_subject_sha256", "marker_sha256")
            fields(rule, ("kind", "finding_id", "identity_path", "subject_field", "marker_field", *keys))
            require(all(isinstance(rule[k], str) and SHA.fullmatch(rule[k]) for k in keys)
                    and len({rule[k] for k in keys}) == 3, "distinct subject and marker hashes required")
            identifier(rule["subject_field"])
            identifier(rule["marker_field"])
            require(isinstance(rule["identity_path"], str) and
                    re.fullmatch(r"/[A-Za-z0-9_/-]+", rule["identity_path"])
                    and rule["identity_path"] != endpoint(target).path, "invalid identity route")
        require(isinstance(rule["finding_id"], str) and re.fullmatch(r"[1-9][0-9]{0,18}", rule["finding_id"]),
                "invalid standalone finding ID")
        urls = [endpoint(u) for u in (target, control)]
        origins = {(u.hostname.lower().rstrip("."), u.port or (443 if u.scheme == "https" else 80)) for u in urls}
        require(len(origins) == 2, "control must use a distinct reference origin")
        require(urls[0].scheme == urls[1].scheme and urls[0].path == urls[1].path
                and urls[0].query == urls[1].query, "control must use the same scheme, path and query")
    elif kind == "tcp.exposure":
        fields(rule, ("kind", "port"))
        integer(rule["port"], 1, 65535)
        for host in (target, control):
            require(str(ipaddress.ip_address(host)) == host, "expected canonical IP")
    elif kind == "postgres.superuser":
        fields(rule, ("kind", "role"))
        identifier(rule["role"])
        for host in (target, control):
            identifier(host)
    else:
        fields(rule, ("kind", "detector"))
        require(isinstance(rule["detector"], str) and 0 < len(rule["detector"]) <= 240, "invalid detector")
        for host in (target, control):
            identifier(host)


def capture(state, fingerprint, time=0):
    return {"outcome": state, "capture": fingerprint, "time": time, "ref": fingerprint}


def nmap(data, asset, port):
    require(len(data) <= MAX_DOCUMENT and b"<!ENTITY" not in data.upper() and b"\0" not in data,
            "invalid Nmap XML")
    try:
        root = ElementTree.fromstring(data.decode("utf-8"))
    except (ElementTree.ParseError, UnicodeError) as exc:
        raise Invalid("invalid Nmap XML") from exc
    require(root.tag == "nmaprun" and root.get("scanner") == "nmap", "unexpected Nmap root")
    finished = root.find("./runstats/finished")
    if finished is None or finished.get("exit") != "success":
        return []
    start = integer(int(root.get("start", "0")), 1, 2**53-1)
    samples = []
    for host in root.findall("host"):
        if not any(a.get("addr") == asset for a in host.findall("address")):
            continue
        for entry in host.findall("ports/port"):
            if entry.get("protocol") != "tcp" or entry.get("portid") != str(port):
                continue
            state = entry.find("state")
            outcome = {"open": "present", "closed": "absent"}.get(
                None if state is None else state.get("state"), "unknown")
            samples.append(capture(outcome, digest(f"nmap:{asset}:{port}:{start}".encode()), start))
    return samples


def postgres(data, asset, role):
    obj = strict_json(data)
    fields(obj, ("database", "captured_at", "role", "rolsuper"))
    require(type(obj["rolsuper"]) is bool, "expected boolean rolsuper")
    if obj["database"] != asset or obj["role"] != role:
        return []
    ts = integer(obj["captured_at"], 1, 2**53-1)
    return [capture("present" if obj["rolsuper"] else "absent",
                    digest(f"postgres:{asset}:{role}:{ts}".encode()), ts)]


def scanner_signal(data, kind, detector):
    obj = strict_json(data)
    if kind == "testssl":
        require(isinstance(obj, list), "expected flat testssl JSON")
        hit = any(row.get("id") == detector and row.get("severity") in {"LOW","MEDIUM","HIGH","CRITICAL"}
                  for row in obj)
        return [capture("signal" if hit else "unknown", digest(data))]
    require(isinstance(obj, dict), "expected scanner JSON")
    if kind == "forge":
        hits = [case for suite in obj.values() for case, result in suite["test_results"].items()
                if result.get("status") == "Failure"]
    elif kind == "echidna":
        hits = [test["name"] for test in obj["tests"] if test.get("status") == "solved"]
    elif kind == "semgrep":
        hits = [x["check_id"] for x in obj["results"]]
    elif kind == "trivy":
        hits = [v["VulnerabilityID"] for r in obj["Results"] for v in (r.get("Vulnerabilities") or [])]
    elif kind == "zap":
        hits = [str(a["pluginid"]) for site in obj["site"] for a in site["alerts"]]
    else:
        require(obj.get("success") is True, "Slither scan did not complete")
        hits = [d["check"] for d in obj["results"]["detectors"]]
    return [capture("signal" if detector in hits else "unknown", digest(data))]


def samples(data, asset, rule):
    kind = rule["kind"]
    if kind.startswith("http."):
        return traffic_samples(data, asset, rule)
    require(len(data) <= MAX_DOCUMENT, "scanner input too large")
    if kind == "tcp.exposure":
        return nmap(data, asset, rule["port"])
    if kind == "postgres.superuser":
        return postgres(data, asset, rule["role"])
    return scanner_signal(data, kind, rule["detector"])
