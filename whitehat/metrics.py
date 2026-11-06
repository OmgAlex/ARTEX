"""Selective benchmark metrics against separately supplied operator labels."""
import math
from pathlib import Path

from .common import MAX_DOCUMENT, fields, local_bytes, require, strict_json


def wilson95(success, total):
    if not total:
        return None
    z = 1.95996398454
    p = success / total
    denom = 1 + z*z/total
    mid = (p + z*z/(2*total)) / denom
    half = z * math.sqrt(p*(1-p)/total + z*z/(4*total**2)) / denom
    return [max(0, mid-half), min(1, mid+half)]


def score(pairs):
    tp = fp = tn = fn = abstained = positives = 0
    for status, truth in pairs:
        positives += truth
        if status == "confirmed":
            tp += truth
            fp += not truth
        elif status == "not_reproduced":
            tn += not truth
            fn += truth
        else:
            abstained += 1
    n = len(pairs)
    return {"cases": n, "confirmed_true": tp, "confirmed_false": fp, "negative_true": tn,
            "negative_false": fn, "abstained": abstained, "positives_in_truth": positives,
            "precision": tp/(tp+fp) if tp+fp else None, "precision_95_interval": wilson95(tp, tp+fp),
            "recall_including_abstentions": tp/positives if positives else None,
            "decision_coverage": (n-abstained)/n if n else None}


def benchmark(report, label_path):
    path = Path(label_path).resolve()
    labels = strict_json(local_bytes(path.parent, path.name, MAX_DOCUMENT))
    require(isinstance(labels, dict) and set(labels) == {c["id"] for c in report["cases"]},
            "supply one independent label per case")
    groups = {}
    pairs = []
    for c in report["cases"]:
        label = labels[c["id"]]
        fields(label, ("revision", "present"))
        require(label["revision"] == c["revision"] and type(label["present"]) is bool,
                "label revision or type mismatch")
        pair = (c["status"], label["present"])
        pairs.append(pair)
        groups.setdefault(c["rule"]["kind"], []).append(pair)
    report["benchmark"] = {"overall": score(pairs), "by_rule": {k:score(v) for k,v in groups.items()}}
