"""Evidence ledger and conservative decision rules; model outputs have no vote."""
from collections import Counter
from pathlib import Path

from .adapters import SIGNALS, samples, validate_rule
from .common import (MAX_CASES, MAX_DOCUMENT, MAX_RUNS, SHA, Invalid, digest, fields, identifier,
                     integer, local_bytes, require, rows, strict_json)

POLICY_VERSION = "whitehat-report/1"
STATUSES = ("confirmed", "corroborated", "observed", "hypothesis", "conflicting",
            "not_reproduced", "insufficient", "invalid_evidence")
MAX_INPUT_TOTAL = 256 * 1024 * 1024


def scope_check(case):
    fields(case, ("id", "rule", "target", "control", "revision", "window", "runs"))
    identifier(case["id"])
    identifier(case["revision"])
    for key in ("target", "control"):
        require(isinstance(case[key], str) and 0 < len(case[key]) <= 2048, "invalid scoped asset")
    require(case["target"] != case["control"], "control must be a distinct reference")
    bounds = rows(case["window"], 2, 2)
    start, end = [integer(value, 1, 253402300799) for value in bounds]
    require(start <= end and end-start <= 31*86400, "window must cover at most 31 days")
    validate_rule(case["rule"], case["target"], case["control"])
    runs = rows(case["runs"], MAX_RUNS)
    ids = set()
    for run in runs:
        fields(run, ("id", "side", "file", "sha256", "revision", "collector"), ("finding_id",))
        if "finding_id" in run:
            require(case["rule"]["kind"].startswith("http."), "finding_id is only for ARTEX exports")
            validate_rule(case["rule"] | {"finding_id": run["finding_id"]}, case["target"], case["control"])
        key = identifier(run["id"])
        require(key not in ids, "duplicate run identifier")
        ids.add(key)
        require(run["side"] in ("target", "control"), "invalid run side")
        identifier(run["collector"])
        require(run["revision"] == case["revision"], "run from another revision")
        require(isinstance(run["sha256"], str) and SHA.fullmatch(run["sha256"]), "invalid pinned digest")


def audit_run(root, case, run, remaining):
    view = {"id": run["id"], "side": run["side"], "collector": run["collector"],
            "sha256": run["sha256"], "items": []}
    try:
        data = local_bytes(root, run["file"], min(64*1024*1024, remaining[0]))
        remaining[0] -= len(data)
        require(digest(data) == run["sha256"], "archive differs from operator-pinned digest")
        rule = case["rule"]
        if "finding_id" in run:
            rule = rule | {"finding_id": run["finding_id"]}
        if "finding_id" in rule:
            view["finding_id"] = rule["finding_id"]
        items = samples(data, case[run["side"]], rule)
        lo, hi = case["window"]
        for item in items:
            start, end = item.get("span", [item["time"], item["time"]])
            if start and not lo <= start <= end <= hi:
                item["outcome"] = "unknown"
                item["reason"] = "outside_window"
        view["items"] = items
    except (ValueError, OSError, TypeError, KeyError, AttributeError, RecursionError, OverflowError) as exc:
        view["error"] = str(exc) if isinstance(exc, Invalid) else "unreadable or unexpected input format"
    return view


def distinct_positive_runs(runs):
    earlier = []
    for run in runs:
        good = [s for s in run["items"] if s["outcome"] == "present"]
        if not good:
            continue
        captures = {s["capture"] for s in good}
        times = {s["time"] for s in good}
        refs = {ref for s in good for ref in [s["ref"], *s.get("support_refs", [])]}
        for prev, prev_captures, prev_times, prev_refs in earlier:
            if (run["collector"] != prev["collector"] and run["sha256"] != prev["sha256"]
                    and captures.isdisjoint(prev_captures) and times.isdisjoint(prev_times)
                    and refs.isdisjoint(prev_refs)):
                return True
        earlier.append((run, captures, times, refs))
    return False


def decide(rule, runs):
    targets = [r for r in runs if r["side"] == "target"]
    controls = [r for r in runs if r["side"] == "control"]
    def outcomes(group):
        return {i["outcome"] for r in group for i in r["items"]}
    t, c = outcomes(targets), outcomes(controls)
    empty = any(not r["items"] or "unknown" in outcomes([r]) for r in runs)
    proof = "present" in t
    repeat = distinct_positive_runs(targets)
    control = "absent" in c and c == {"absent"}
    conflict = (proof and "absent" in t) or "present" in c
    invalid = any("error" in r for r in runs)
    gates = {"direct_observation": proof, "independent_repeat": repeat, "negative_control": control,
             "all_inputs_comparable": bool(runs) and not empty and not invalid,
             "contradiction": conflict, "integrity_error": invalid}
    if invalid:
        status = "invalid_evidence"
    elif rule["kind"] in SIGNALS:
        status = "hypothesis" if "signal" in t else "insufficient"
    elif conflict:
        status = "conflicting"
    elif proof and repeat and control and not empty:
        status = "confirmed"
    elif proof and repeat:
        status = "corroborated"
    elif proof:
        status = "observed"
    elif t == {"absent"} and not empty and control:
        status = "not_reproduced"
    else:
        status = "insufficient"
    return status, gates


def evaluate(manifest_path):
    path = Path(manifest_path).resolve()
    spec = strict_json(local_bytes(path.parent, path.name, MAX_DOCUMENT))
    fields(spec, ("schema", "cases"))
    require(spec["schema"] == POLICY_VERSION, "unsupported manifest schema")
    results = []
    ids = set()
    budget = [MAX_INPUT_TOTAL]
    for case in rows(spec["cases"], MAX_CASES, 1):
        scope_check(case)
        require(case["id"] not in ids, "duplicate case identifier")
        ids.add(case["id"])
        runs = [audit_run(path.parent, case, r, budget) for r in case["runs"]]
        status, gates = decide(case["rule"], runs)
        results.append({"id": case["id"], "rule": case["rule"], "target": case["target"],
                        "control": case["control"], "revision": case["revision"], "window": case["window"],
                        "status": status, "gates": gates, "runs": runs})
    counts = Counter(c["status"] for c in results)
    return {"schema": POLICY_VERSION, "cases": results, "counts": {s: counts[s] for s in STATUSES}}
