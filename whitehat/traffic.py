"""Read ARTEX md-zip exports at the native evidence/{finding}/{binding} paths."""
import io
import json
import re
import zipfile
from urllib.parse import urlsplit

from .common import Invalid, MAX_DOCUMENT, SHA, digest, integer, require, strict_json

MANIFEST = re.compile(r"evidence/([1-9][0-9]*)/([1-9][0-9]*)/manifest\.json\Z")
HEADER = re.compile(r"[!#$%&'*+.^_`|~0-9a-zA-Z-]+\Z")
STATUS = re.compile(r"HTTP(?:/\d+(?:\.\d+)?)? ([0-9]{3})(?: [^\r\n]*)?\Z")
MAX_MEMBERS = 8192
MAX_SELECTED = 128
MAX_HEADERS = 64 * 1024
MAX_INFLATED = 128 * 1024 * 1024


def endpoint(value):
    require(isinstance(value, str) and len(value) < 2048 and value.isascii()
            and not any(ord(c) <= 32 or ord(c) == 127 for c in value), "invalid endpoint")
    url = urlsplit(value)
    require(url.scheme in {"http", "https"} and url.hostname and url.username is None
            and url.password is None and not url.fragment, "expected exact HTTP endpoint")
    return url


def headers(raw):
    require(isinstance(raw, str) and len(raw) <= MAX_HEADERS, "invalid HTTP headers")
    lines = raw.replace("\r\n", "\n").rstrip("\n").split("\n")
    require(lines and all("\r" not in line and "\0" not in line for line in lines), "invalid HTTP framing")
    parsed = {}
    for line in lines[1:]:
        key, sep, val = line.partition(":")
        require(sep and HEADER.fullmatch(key) and all(ord(c) >= 32 or c == "\t" for c in val),
                "incomplete or ambiguous HTTP headers")
        parsed.setdefault(key.lower(), []).append(val.strip())
    return lines[0], parsed


def get_entry(archive, name, limit):
    try:
        entry = archive.getinfo(name)
        require(entry.file_size <= limit and not entry.flag_bits & 1, "unsupported ZIP entry")
        return archive.read(entry)
    except (KeyError, zipfile.BadZipFile, NotImplementedError, RuntimeError) as exc:
        raise Invalid("missing, corrupt or unsupported ZIP entry") from exc


def check_wire(archive, prefix, snap, side, short):
    head = snap.get(short + "_head")
    first, parsed = headers(head)
    body = get_entry(archive, prefix + side + ".bin", MAX_DOCUMENT)
    require(type(snap.get(short + "_len")) is int and len(body) == snap[short + "_len"]
            and digest(body) == snap.get(short + "_hash"), "body length or digest mismatch")
    message = get_entry(archive, prefix + side + ".http", MAX_DOCUMENT + MAX_HEADERS + 2)
    require(message == head.rstrip("\r\n").encode() + b"\n\n" + body, "HTTP message differs from manifest")
    return first, parsed, body


def snapshot_hash(snap):
    # db.TrafficSnapshotID serializes the Go struct in declaration order with
    # an empty ID and zero CreatedAt. encoding/json escapes HTML and U+2028/9.
    obj = {"id": ""}
    for key in ("source_traffic_id", "captured_at", "url", "method", "status", "content_type",
                "req_head", "resp_head", "req_hash", "resp_hash", "req_len", "resp_len"):
        if key not in ("req_head", "resp_head") or snap.get(key):
            require(key in snap, "incomplete native snapshot")
            obj[key] = snap[key]
    obj["created_at"] = "0001-01-01T00:00:00Z"
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    for char in "<>&\u2028\u2029":
        raw = raw.replace(char, "\\u%04x" % ord(char))
    return digest(raw.encode())


def read_http(archive, prefix, binding, snap, asset):
    require(snapshot_hash(snap) == snap["id"], "native snapshot digest mismatch")
    req, req_headers, _ = check_wire(archive, prefix, snap, "request", "req")
    resp, response_headers, body = check_wire(archive, prefix, snap, "response", "resp")
    url = endpoint(asset)
    request_target = (url.path or "/") + ("?" + url.query if url.query else "")
    require(req.split()[:2] == [snap.get("method"), request_target], "request line mismatch")
    hosts = req_headers.get("host", [])
    require(len(hosts) == 1 and hosts[0].lower() == url.netloc.lower(), "request host mismatch")
    status = STATUS.fullmatch(resp)
    require(status and int(status[1]) == snap.get("status"), "response status mismatch")
    source = snap.get("source_traffic_id")
    require(isinstance(source, str) and 0 < len(source) <= 128, "invalid capture identifier")
    timestamp = integer(snap.get("captured_at"), 1, 2**53 - 1)
    return {"method": snap["method"], "status": snap["status"], "req": req_headers,
            "resp": response_headers, "body": body, "url": asset, "capture": digest(source.encode()),
            "time": timestamp, "ref": binding["snapshot_id"]}


def nosniff(record, media):
    response_headers = record["resp"]
    types = response_headers.get("content-type", [])
    comparable = (record["method"] == "GET" and record["status"] == 200 and len(types) == 1
                  and types[0].split(";")[0].strip().lower() == media)
    values = response_headers.get("x-content-type-options", [])
    # A duplicated header is ambiguous. Do not infer browser behavior from it.
    outcome = "unknown"
    if comparable and len(values) <= 1:
        outcome = "absent" if values and values[0].lower() == "nosniff" else "present"
    return {k: record[k] for k in ("capture", "time", "ref")} | {"outcome": outcome}


def traffic_samples(data, asset, rule):
    url = endpoint(asset)
    private = rule["kind"] == "http.private_json"
    identity = url._replace(path=rule["identity_path"], query="").geturl() if private else None
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise Invalid("invalid ARTEX ZIP") from exc
    found = []
    with archive:
        infos = archive.infolist()
        require(len(infos) <= MAX_MEMBERS and len({i.filename for i in infos}) == len(infos),
                "too many or duplicate ZIP members")
        require(sum(i.file_size for i in infos) <= MAX_INFLATED, "ZIP exceeds expanded size limit")
        entries = [(i.filename, MANIFEST.fullmatch(i.filename)) for i in infos]
        for name, match in entries:
            if not match or match[1] != rule["finding_id"]:
                continue
            binding = strict_json(get_entry(archive, name, MAX_HEADERS * 3))
            require(isinstance(binding, dict) and binding.get("finding_id") == match[1]
                    and binding.get("id") == match[2], "binding identity mismatch")
            snap = binding.get("snapshot")
            require(isinstance(snap, dict) and isinstance(snap.get("id"), str)
                    and SHA.fullmatch(snap["id"]) and snap["id"] == binding.get("snapshot_id"),
                    "snapshot identity mismatch")
            if snap.get("url") == asset or (private and snap.get("url") == identity):
                require(len(found) < MAX_SELECTED, "too many captures for one run")
                found.append(read_http(archive, name.rsplit("/", 1)[0] + "/", binding, snap, snap["url"]))
    if private:
        from .private_json import private_samples
        return private_samples(found, asset, identity, rule)
    return [nosniff(record, rule["media_type"]) for record in found]
