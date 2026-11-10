"""Classifier defense fixes and the localhost classifier service, tested with a fake model
backend (no torch needed): score scale regression, response-shape parsing, windowing, and the
whole HTTP path from ClassifierDefense through netguard to services/classifier_server.py."""
from __future__ import annotations

import threading
import unittest
from unittest import mock

from _common import ROOT

import sys
sys.path.insert(0, str(ROOT / "services"))

from classifier_server import Scorer, serve, windows  # noqa: E402

from rtbt import netguard  # noqa: E402
from rtbt.defenses import ClassifierDefense, HttpClassifierAdapter, build_defense  # noqa: E402
from rtbt.schemas import ConfigurationError  # noqa: E402


class FakeBackend:
    """Whitespace 'tokenizer'; P(injection) = 0.9 if a window contains the word IGNORE, else 0.05."""
    model_name = "fake/injection-detector"
    revision = "test"

    def __init__(self):
        self.calls = []

    def encode(self, text):
        return text.split()

    def decode(self, ids):
        return " ".join(ids)

    def p_injection(self, texts):
        self.calls.append(list(texts))
        return [0.9 if "IGNORE" in t.split() else 0.05 for t in texts]


def adapter_with(response):
    a = HttpClassifierAdapter("http://127.0.0.1:9/score", "m", allowlist=("127.0.0.1",))
    return a, mock.patch("rtbt.netguard.post_json", return_value=(response, 1.0))


class HttpAdapterScale(unittest.TestCase):
    def test_probability_is_not_rescaled_so_threshold_means_what_it_says(self):
        # Regression: before WB2 a p=0.2 came back as 1.0 and tripped a 0.5 threshold.
        a, patch = adapter_with({"score": 0.2, "label": "BENIGN"})
        with patch:
            self.assertTrue(ClassifierDefense(backend=a, threshold=0.5).inspect_content("x").allowed)
        a, patch = adapter_with({"score": 0.51, "label": "INJECTION"})
        with patch:
            self.assertFalse(ClassifierDefense(backend=a, threshold=0.5).inspect_content("x").allowed)

    def test_hugging_face_response_shapes(self):
        cases = [
            ([{"label": "INJECTION", "score": 0.8}], 0.8),
            ([{"label": "SAFE", "score": 0.7}], 0.3),                                   # top label only, negative
            ([[{"label": "LABEL_0", "score": 0.4}, {"label": "LABEL_1", "score": 0.6}]], 0.6),  # all labels, nested
            ([{"label": "BENIGN", "score": 0.5}, {"label": "NEUTRAL", "score": 0.5}], 0.0),
        ]
        for response, expected in cases:
            a, patch = adapter_with(response)
            with patch:
                self.assertAlmostEqual(a.score("x")[0], expected, msg=str(response))

    def test_out_of_range_or_unknown_responses_raise_instead_of_guessing(self):
        for response in ({"score": 3.0}, [1, 2], "nope"):
            a, patch = adapter_with(response)
            with patch, self.assertRaises(netguard.NetError):
                a.score("x")

    def test_build_defense_http_default_threshold_is_half(self):
        d = build_defense("classifier", classifier_spec={"backend": "http", "endpoint": "http://127.0.0.1:9/score"})
        self.assertEqual(d.threshold, 0.5)
        self.assertEqual(d.provenance, "real_model")


class Windowing(unittest.TestCase):
    def test_every_token_is_covered_and_tail_is_right_aligned(self):
        for n in (0, 1, 511, 512, 513, 1000, 1537):
            spans = windows(list(range(n)), 512, 256)
            covered = set()
            for a, b in spans:
                self.assertLessEqual(b - a, 512)
                covered.update(range(a, b))
            self.assertEqual(covered, set(range(n)))
            if n > 512:
                self.assertEqual(spans[-1], (n - 512, n))

    def test_bad_parameters(self):
        with self.assertRaises(ValueError):
            windows([1], 512, 0)
        with self.assertRaises(ValueError):
            windows([1], 512, 600)

    def test_injection_past_the_first_window_is_still_caught(self):
        text = " ".join(["filler"] * 900 + ["IGNORE"] + ["filler"] * 50)
        out = Scorer(FakeBackend()).score(text)
        self.assertEqual(out["score"], 0.9)
        self.assertGreater(out["max_window"], 0)
        self.assertGreater(out["windows"], 1)
        short = Scorer(FakeBackend()).score("hello there")
        self.assertEqual((short["windows"], short["label"]), (1, "BENIGN"))


class EndToEndOverHttp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = serve(Scorer(FakeBackend(), max_tokens=8, stride=4), "127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _defense(self):
        return build_defense("classifier", classifier_spec={
            "backend": "http", "endpoint": f"http://127.0.0.1:{self.port}/score", "model_name": "fake",
            "threshold": 0.5, "allowlist": ["127.0.0.1"]})

    def test_classifier_defense_blocks_and_allows_through_the_real_service(self):
        d = self._defense()
        blocked = d.inspect_content("a b c d e f g h i j IGNORE k")
        self.assertFalse(blocked.allowed)
        self.assertAlmostEqual(blocked.risk_score, 0.9)
        self.assertTrue(d.inspect_content("an ordinary meeting note").allowed)

    def test_service_rejects_bad_requests(self):
        import json
        import urllib.error
        import urllib.request
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/score", data=json.dumps({"x": 1}).encode(),
                                     method="POST", headers={"Content-Type": "application/json"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 400)
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/health", timeout=5) as r:
            self.assertEqual(json.loads(r.read())["model"], "fake/injection-detector")

    def test_hosts_off_the_allowlist_are_refused_before_any_request(self):
        d = build_defense("classifier", classifier_spec={
            "backend": "http", "endpoint": f"http://127.0.0.1:{self.port}/score", "allowlist": ["10.0.0.1"]})
        with self.assertRaises(ConfigurationError):
            d.inspect_content("x")

    def test_service_outage_mid_experiment_gives_invalid_rounds_not_a_crash(self):
        from rtbt.harness import ExperimentConfig, ExperimentRunner
        from _common import SUITE
        cfg = ExperimentConfig(defenses=("classifier",), attack_modes=("static",), attack_budget=4, seeds=(1,),
                               scenario_ids=("email-summary-exfil",),
                               classifier_spec={"backend": "http", "endpoint": "http://127.0.0.1:1/score",
                                                "allowlist": ["127.0.0.1"]},
                               network_allowlist=("127.0.0.1",))
        report = ExperimentRunner(suite=SUITE, config=cfg).run()
        rounds = report.campaigns[0].rounds
        self.assertTrue(rounds and all(not r.valid and r.error_category == "defense_error" for r in rounds))


if __name__ == "__main__":
    unittest.main()
