import io
import json
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

from .adapters import samples
from .common import Invalid, digest
from .demo import DEMO_TIME, demo, export_zip
from .traffic import snapshot_hash
from .verify import evaluate


def rewrite(raw, transform):
    result = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw)) as src, zipfile.ZipFile(result, "w") as dst:
        for name in src.namelist():
            data = transform(name, src.read(name))
            if data is not None:
                dst.writestr(name, data)
    return result.getvalue()


class Collection(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        self.manifest = demo(self.home/"inputs")
        self.root = self.manifest.parent
        self.spec = json.loads(self.manifest.read_text())
        self.case = self.spec["cases"][0]
        self.runs = self.case["runs"]

    def result(self):
        self.manifest.write_text(json.dumps(self.spec))
        return evaluate(self.manifest)["cases"][0]

    def status(self):
        return self.result()["status"]

    def replace(self, index, data):
        run = self.runs[index]
        (self.root/run["file"]).write_bytes(data)
        run["sha256"] = digest(data)

    def test_confirmed_with_three_captures(self):
        self.assertEqual(self.status(), "confirmed")

    def test_one_target_only(self):
        self.runs.pop(1)
        self.assertEqual(self.status(), "observed")

    def test_no_negative_control(self):
        self.runs.pop()
        self.assertEqual(self.status(), "corroborated")

    def test_same_collector(self):
        self.runs[1]["collector"] = self.runs[0]["collector"]
        self.assertEqual(self.status(), "observed")

    def test_repacked_capture(self):
        data = (self.root/self.runs[0]["file"]).read_bytes()
        self.replace(1, rewrite(data, lambda k, v: v))
        self.assertEqual(self.status(), "observed")

    def test_same_timestamp_different_id(self):
        self.replace(1, export_zip(self.case["target"], DEMO_TIME, header=False, source="other"))
        self.assertEqual(self.status(), "observed")

    def test_same_source_different_timestamp(self):
        self.replace(1, export_zip(self.case["target"], DEMO_TIME+3, header=False, source=f"{DEMO_TIME}-0001"))
        self.assertEqual(self.status(), "observed")

    def test_conflict_on_target(self):
        self.replace(1, export_zip(self.case["target"], DEMO_TIME+1))
        self.assertEqual(self.status(), "conflicting")

    def test_contaminated_control(self):
        self.replace(2, export_zip(self.case["control"], DEMO_TIME+2, header=False))
        self.assertEqual(self.status(), "conflicting")

    def test_fixed_revision(self):
        for n in (0, 1):
            self.replace(n, export_zip(self.case["target"], DEMO_TIME+n))
        self.assertEqual(self.status(), "not_reproduced")

    def test_redirect_is_inconclusive(self):
        self.replace(1, export_zip(self.case["target"], DEMO_TIME+1, header=False, status=302))
        self.assertEqual(self.status(), "observed")

    def test_login_html_is_inconclusive(self):
        self.replace(1, export_zip(self.case["target"], DEMO_TIME+1, header=False, media="text/html"))
        self.assertEqual(self.status(), "observed")

    def test_out_of_window(self):
        self.case["window"][0] += 1
        self.assertEqual(self.status(), "observed")

    def test_different_route(self):
        self.replace(1, export_zip("https://other.test/api/ping", DEMO_TIME+1, header=False))
        self.assertEqual(self.status(), "observed")

    def test_changed_archive(self):
        self.runs[2]["sha256"] = "0"*64
        self.assertEqual(self.status(), "invalid_evidence")

    def test_changed_body_even_with_new_archive_digest(self):
        raw = (self.root/self.runs[0]["file"]).read_bytes()
        self.replace(0, rewrite(raw, lambda k,v: b"altered" if k.endswith("response.bin") else v))
        self.assertEqual(self.status(), "invalid_evidence")

    def test_missing_raw_request(self):
        raw = (self.root/self.runs[0]["file"]).read_bytes()
        self.replace(0, rewrite(raw, lambda k,v: None if k.endswith("request.http") else v))
        self.assertEqual(self.status(), "invalid_evidence")

    def test_changed_capture_timestamp(self):
        raw = (self.root/self.runs[0]["file"]).read_bytes()
        self.replace(0, rewrite(raw, lambda k,v: v.replace(str(DEMO_TIME).encode(), b"1700000000")
                                if k.endswith("manifest.json") else v))
        self.assertEqual(self.status(), "invalid_evidence")

    def test_duplicate_zip_entry(self):
        buf = io.BytesIO((self.root/self.runs[0]["file"]).read_bytes())
        with warnings.catch_warnings(), zipfile.ZipFile(buf, "a") as f:
            warnings.simplefilter("ignore")
            f.writestr("evidence/42/17/request.bin", b"")
        self.replace(0, buf.getvalue())
        self.assertEqual(self.status(), "invalid_evidence")

    def test_side_reference_path(self):
        self.runs[0]["file"] = "../outside.zip"
        self.assertEqual(self.status(), "invalid_evidence")

    def test_control_origin_alias_rejected(self):
        self.case["control"] = "https://FIXTURE.TEST:443/api/ping"
        with self.assertRaises(Invalid):
            self.result()

    def test_different_revision(self):
        self.runs[0]["revision"] = "different"
        with self.assertRaises(Invalid):
            self.result()


def private_bundle(host, ts, peer_body, peer_status, who="peer", media="application/json"):
    records = [("/identity", "alpha", {"sub": "owner"}, 200, "application/json"),
               ("/identity", "beta", {"sub": who}, 200, "application/json"),
               ("/objects/1", "alpha", {"marker": "fixture-marker"}, 200, "application/json"),
               ("/objects/1", "beta", peer_body, peer_status, media)]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as dest:
        for n, (path, token, obj, status, ct) in enumerate(records):
            body = json.dumps(obj).encode()
            raw = export_zip(host+path, ts+n, source=f"{ts}-{n}", status=status, body=body, media=ct)
            with zipfile.ZipFile(io.BytesIO(raw)) as src:
                key = "evidence/42/17/"
                binding = json.loads(src.read(key+"manifest.json"))
                snap = binding["snapshot"]
                snap["req_head"] += "Authorization: Bearer " + token + "\n"
                snap["id"] = snapshot_hash(snap)
                binding.update({"snapshot_id": snap["id"], "id": str(n+1)})
                prefix = f"evidence/42/{n+1}/"
                for k in src.namelist():
                    value = src.read(k)
                    if k.endswith("manifest.json"):
                        value = json.dumps(binding).encode()
                    elif k.endswith("request.http"):
                        value = snap["req_head"].rstrip().encode()+b"\n\n"
                    dest.writestr(prefix+k[len(key):], value)
    return buf.getvalue()


class PrivateObject(unittest.TestCase):
    def setUp(self):
        self.host = "https://local.test"
        self.rule = {"kind": "http.private_json", "finding_id":"42", "identity_path":"/identity",
                     "subject_field":"sub", "marker_field":"marker", "marker_sha256":digest(b"fixture-marker"),
                     "peer_subject_sha256":digest(b"peer"), "owner_subject_sha256":digest(b"owner")}

    def states(self, body, status=200, **kwargs):
        raw = private_bundle(self.host, DEMO_TIME, body, status, **kwargs)
        rows = samples(raw, self.host+"/objects/1", self.rule)
        encoded = json.dumps(rows)
        self.assertNotIn("Bearer", encoded)
        self.assertNotIn("fixture-marker", encoded)
        return [r["outcome"] for r in rows]

    def test_direct_observation(self):
        self.assertEqual(self.states({"marker":"fixture-marker"}), ["present"])

    def test_denial(self):
        self.assertEqual(self.states({"error":"forbidden"}, 403), ["absent"])

    def test_denial_leaking_exact_private_marker_is_positive(self):
        self.assertEqual(self.states({"marker":"fixture-marker"}, 403), ["present"])

    def test_same_account_two_credentials(self):
        self.assertNotIn("present", self.states({"marker":"fixture-marker"}, who="owner"))

    def test_login_with_200(self):
        self.assertEqual(self.states({"marker":"fixture-marker"}, media="text/html"), ["unknown"])

    def test_public_wrapper_or_wrong_object(self):
        self.assertEqual(self.states({"ok":True}), ["unknown"])

    def test_expired_credentials(self):
        self.assertEqual(self.states({"error":"unauthenticated"}, 401), ["unknown"])

    def test_whole_private_object_case_with_independent_runs_and_control(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = demo(Path(tmp)/"inputs")
            spec = json.loads(manifest.read_text())
            case = spec["cases"][0]
            case["rule"] = self.rule
            case["target"] = "https://target.test/objects/1"
            case["control"] = "https://control.test/objects/1"
            for n, run in enumerate(case["runs"]):
                control = run["side"] == "control"
                host = case[run["side"]].removesuffix("/objects/1")
                body = {"error":"forbidden"} if control else {"marker":"fixture-marker"}
                buf = private_bundle(host, DEMO_TIME+10*n, body, 403 if control else 200)
                (manifest.parent/run["file"]).write_bytes(buf)
                run["sha256"] = digest(buf)
            manifest.write_text(json.dumps(spec))
            result = evaluate(manifest)["cases"][0]
            self.assertEqual(result["status"], "confirmed")
            self.assertEqual(len(result["runs"][1]["items"][0]["support_refs"]), 3)
            # Independent label change: a patched target denies the peer too.
            for n, run in enumerate(case["runs"][:2]):
                buf = private_bundle("https://target.test", DEMO_TIME+10*n, {"error":"forbidden"}, 403)
                (manifest.parent/run["file"]).write_bytes(buf)
                run["sha256"] = digest(buf)
            manifest.write_text(json.dumps(spec))
            self.assertEqual(evaluate(manifest)["cases"][0]["status"], "not_reproduced")
