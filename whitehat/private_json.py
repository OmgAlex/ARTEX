"""Verify a private synthetic object's disclosure from saved HTTP exchanges only."""
from .common import Invalid, digest, strict_json

MAX_SKEW = 300


def field_hash(record, field):
    types = record["resp"].get("content-type", [])
    if len(types) != 1 or types[0].split(";")[0].strip().lower() != "application/json":
        return None
    try:
        obj = strict_json(record["body"])
    except Invalid:
        return None
    value = obj.get(field) if isinstance(obj, dict) else None
    return digest(value.encode()) if isinstance(value, str) else None


def credential(record):
    keys = record["req"].get("authorization", [])
    if ("cookie" in record["req"] or len(keys) != 1 or not keys[0].lower().startswith("bearer ")
            or len(keys[0].split()) != 2):
        return None
    return digest(keys[0].encode())


def principal(record, identities, rule):
    token = credential(record)
    if not token:
        return None
    matches = {field_hash(i, rule["subject_field"]) if i["status"] == 200 else None for i in identities
               if credential(i) == token and abs(i["time"] - record["time"]) <= MAX_SKEW}
    return matches.pop() if len(matches) == 1 else None


def private_samples(records, target, identity, rule):
    identities = [r for r in records if r["url"] == identity and r["method"] == "GET"]
    owners, others = [], []
    for r in records:
        if r["url"] != target:
            continue
        who = principal(r, identities, rule)
        if r["method"] == "GET" and who == rule["owner_subject_sha256"]:
            owners.append(r)
        else:
            others.append((r, who))
    results = []
    for r, who in others:
        state = "unknown"
        baseline = [o for o in owners if abs(o["time"] - r["time"]) <= MAX_SKEW]
        known = (r["method"] == "GET" and who == rule["peer_subject_sha256"] and baseline
                 and all(o["status"] == 200 and field_hash(o, rule["marker_field"]) == rule["marker_sha256"]
                         for o in baseline))
        if known:
            marker = field_hash(r, rule["marker_field"])
            if r["status"] == 200 and marker == rule["marker_sha256"]:
                state = "present"
            elif r["status"] in (403, 404) and r["body"] == b"":
                state = "absent"
            elif r["status"] in (403, 404) and marker != rule["marker_sha256"]:
                # Accept only a minimal, known denial envelope. A login page or
                # an error response with arbitrary embedded data is inconclusive.
                try:
                    denial = strict_json(r["body"])
                except Invalid:
                    denial = None
                if denial in ({"error": "forbidden"}, {"error": "not_found"}):
                    state = "absent"
        used = baseline + [i for i in identities if abs(i["time"] - r["time"]) <= 2*MAX_SKEW]
        times = [r["time"]] + [i["time"] for i in used]
        results.append({"outcome": state, "capture": r["capture"], "time": r["time"], "ref": r["ref"],
                        "support_refs": sorted({i["ref"] for i in used}), "span": [min(times), max(times)]})
    return results
