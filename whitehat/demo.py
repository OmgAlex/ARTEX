"""Small offline ARTEX-format evidence fixture. Never contacts any service."""
import io
import json
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

from .common import digest
from .traffic import snapshot_hash
from .verify import POLICY_VERSION

DEMO_TIME = 1793995200


def export_zip(url, ts, header=True, status=200, source=None, body=b'{"ok":true}', media="application/json"):
    host = urlsplit(url).netloc
    path = urlsplit(url).path
    req = f"GET {path} HTTP/1.1\nHost: {host}\n"
    resp = f"HTTP {status}\nContent-Type: {media}\n"
    if header:
        resp += "X-Content-Type-Options: nosniff\n"
    s = {"source_traffic_id": source or f"{ts}-0001", "captured_at": ts, "url": url, "method": "GET",
         "status": status, "content_type": media, "req_head": req, "resp_head": resp,
         "req_hash": digest(b""), "resp_hash": digest(body), "req_len": 0, "resp_len": len(body)}
    s["id"] = snapshot_hash(s)
    s["created_at"] = "2026-11-06T20:00:00Z"
    binding = {"id": "17", "finding_id": "42", "snapshot_id": s["id"], "role": "proof",
               "position": 0, "note": "", "snapshot": s}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        prefix = "evidence/42/17/"
        archive.writestr(prefix + "manifest.json", json.dumps(binding))
        for side, head, raw in [("request", req, b""), ("response", resp, body)]:
            archive.writestr(prefix + side + ".bin", raw)
            archive.writestr(prefix + side + ".http", head.rstrip("\r\n").encode() + b"\n\n" + raw)
    return buf.getvalue()


def demo(dest):
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=False)
    case = {"id": "demo-header", "target": "https://fixture.test/api/ping",
            "control": "https://reference.test/api/ping", "revision": "fixture-v1",
            "rule": {"kind": "http.nosniff", "finding_id": "42", "media_type": "application/json"},
            "window": [DEMO_TIME, DEMO_TIME+60], "runs": []}
    for n, side in enumerate(("target", "target", "control")):
        data = export_zip(case[side], DEMO_TIME+n, header=side == "control")
        fname = f"capture-{n}.zip"
        (dest / fname).write_bytes(data)
        case["runs"].append({"id": f"run-{n}", "side": side, "revision": case["revision"],
                             "file": fname, "sha256": digest(data), "collector": f"fixture-{n}"})
    manifest = dest / "case.json"
    manifest.write_text(json.dumps({"schema": POLICY_VERSION, "cases": [case]}, indent=2)+"\n")
    return manifest
