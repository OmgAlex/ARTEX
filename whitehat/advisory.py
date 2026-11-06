"""Optional tool-less provider calls. Only redacted facts and opaque case/run IDs leave the process."""
import json
import os
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .common import Invalid, fields, integer, require, strict_json

ACTIONS = ("inspect_target", "inspect_control", "compare_repeats")
REASONS = ("matches_rule", "incomplete_capture", "benign_configuration", "different_conditions",
           "conflicting_records", "scanner_only")
NEXT = ("none", "supply_independent_capture", "supply_known_good_control", "review_scope",
        "check_artifact_integrity", "review_scanner_signal")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class Provider:
    def __init__(self, tier):
        prefix = "WHITEHAT_" + tier.upper() + "_"
        url = os.environ.get(prefix + "URL", "")
        parts = urlsplit(url)
        require(parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in
                ("localhost", "127.0.0.1", "::1")), "model endpoint needs HTTPS or loopback")
        require(parts.hostname and not parts.username and not parts.password and not parts.query
                and not parts.fragment, "invalid model endpoint")
        self.url = url.rstrip("/") + "/chat/completions"
        self.model = os.environ.get(prefix + "MODEL", "")
        require(bool(self.model), "model name missing")
        self.key = os.environ.get(prefix + "KEY", "")
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def __call__(self, instruction, data):
        payload = {"model": self.model, "messages": [
            {"role": "system", "content": instruction + " Return only one JSON object. No prose or code."},
            {"role": "user", "content": json.dumps(data, separators=(",", ":"))}],
            "max_tokens": 1200, "stream": False}
        headers = {"Content-Type": "application/json"}
        if self.key:
            headers["Authorization"] = "Bearer " + self.key
        request = urllib.request.Request(self.url, json.dumps(payload).encode(), headers=headers)
        with self.opener.open(request, timeout=20) as resp:
            raw = resp.read(64*1024+1)
        require(len(raw) <= 64*1024, "model output too large")
        return strict_json(strict_json(raw)["choices"][0]["message"]["content"])


def verdict(obj):
    fields(obj, ("reason", "next"))
    require(obj["reason"] in REASONS and obj["next"] in NEXT, "invalid reviewer output")
    return obj


def brief(case):
    return {"rule": case["rule"]["kind"], "status": case["status"], "gates": case["gates"],
            "target_runs": sum(r["side"] == "target" for r in case["runs"]),
            "control_runs": sum(r["side"] == "control" for r in case["runs"])}


def inspect(case, action):
    if action == "compare_repeats":
        return case["gates"]
    side = "target" if action == "inspect_target" else "control"
    return [{"run": i, "states": [item["outcome"] for item in r["items"]], "invalid": "error" in r}
            for i, r in enumerate(case["runs"]) if r["side"] == side]


def advise(report, strong, worker, max_calls):
    integer(max_calls, 1, 128)
    state = {"budget": max_calls, "calls": 0, "processed": 0, "status": "completed"}
    report["model_review"] = state
    def call(model, instructions, payload):
        if state["calls"] >= max_calls:
            raise StopIteration
        state["calls"] += 1
        return model(instructions, payload)
    cases = report["cases"]
    votes = "reason must be one of " + str(REASONS) + "; next must be one of " + str(NEXT)
    try:
        plan = call(strong, "Plan an offline evidence review. Return {order:[...]} with every supplied numeric case index once.",
                    [dict(index=i, **brief(c)) for i, c in enumerate(cases)])
        fields(plan, ("order",))
        order = plan["order"]
        require(isinstance(order, list) and all(type(x) is int for x in order)
                and sorted(order) == list(range(len(cases))), "invalid planner ordering")
        for i in order:
            case = cases[i]
            action = call(worker, "Choose one local evidence tool. Return {action:string}; allowed: " +
                          str(ACTIONS), brief(case))
            fields(action, ("action",))
            require(action["action"] in ACTIONS, "invalid evidence tool")
            record = {"action": action["action"]}
            case["advisory"] = record
            analysis = call(worker, "Assess the observations. Return {reason:string,next:string}. " + votes,
                            {"case": brief(case), "evidence": inspect(case, action["action"])})
            record["worker"] = verdict(analysis)
            if case["status"] in ("conflicting", "invalid_evidence", "insufficient", "hypothesis"):
                review = call(strong, "Review the worker's hypothesis against all evidence gates. Return "
                              "{reason:string,next:string}. " + votes,
                              {"case": brief(case), "worker": analysis})
                record["reviewer"] = verdict(review)
            state["processed"] += 1
    except StopIteration:
        state["status"] = "budget_exhausted"
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError, RecursionError,
            urllib.error.URLError):
        # Provider messages may contain credentials, raw prompts or vendor-specific details.
        state["status"] = "provider_or_schema_error"
