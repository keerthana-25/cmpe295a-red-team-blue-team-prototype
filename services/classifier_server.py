"""Localhost prompt-injection classifier service for the `classifier` defense.

The harness stays stdlib-only: it never imports torch. A real classifier runs here, in a separate
process on the same machine (a Kaggle/Colab GPU session, or a laptop CPU for small runs), and the
ClassifierDefense reaches it through HttpClassifierAdapter, which netguard only allows to talk to
hosts on the allowlist (127.0.0.1 by default).

Models, in order of preference (chosen in WB1, Ch.5):
  primary  meta-llama/Llama-Prompt-Guard-2-86M   (gated on Hugging Face: accept the licence first)
  fallback protectai/deberta-v3-base-prompt-injection-v2  (Apache-2.0, ungated)
Pass --model to pick one; the service records exactly which one answered in every response, and
the harness copies that into the manifest, so a fallback can never be reported as the primary.

Long inputs: both models take at most 512 tokens. A tool output (a whole email thread, a long
document) is split into overlapping 512-token windows (stride 256 by default); each window is
scored and the MAXIMUM P(injection) is returned, because an injection anywhere in the content is
enough to make the content unsafe. Truncating instead would let an attacker hide the payload past
token 512 — a known evasion of single-window classifiers.

API (JSON over HTTP, POST /score):
  request  {"inputs": "<text>"}
  response {"score": p_injection_max, "label": "INJECTION"|"BENIGN", "windows": n,
            "max_window": i, "model": "<hf id>", "revision": "<sha or 'unknown'>", "latency_ms": t}
  GET /health -> {"status": "ok", "model": ..., "max_tokens": 512, "stride": 256}

Run (GPU or CPU):
  pip install torch transformers
  python services/classifier_server.py --model protectai/deberta-v3-base-prompt-injection-v2 --port 8001
and in the experiment config:
  "classifier_spec": {"backend": "http", "endpoint": "http://127.0.0.1:8001/score",
                      "model_name": "protectai/deberta-v3-base-prompt-injection-v2",
                      "threshold": 0.5, "allowlist": ["127.0.0.1"]}
"""
from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Protocol

POSITIVE_LABEL_NAMES = ("INJECTION", "JAILBREAK", "MALICIOUS", "LABEL_1")
MAX_BODY_BYTES = 2_000_000


class Backend(Protocol):
    model_name: str
    revision: str

    def encode(self, text: str) -> list[int]: ...

    def decode(self, ids: list[int]) -> str: ...

    def p_injection(self, texts: list[str]) -> list[float]: ...


def windows(ids: list[int], max_tokens: int, stride: int) -> list[tuple[int, int]]:
    """[start, end) token windows covering every token at least once. The last window is
    right-aligned to the end so no tail is ever dropped."""
    if max_tokens <= 0 or not 0 < stride <= max_tokens:
        raise ValueError("need 0 < stride <= max_tokens")
    if len(ids) <= max_tokens:
        return [(0, len(ids))]
    spans, start = [], 0
    while start + max_tokens < len(ids):
        spans.append((start, start + max_tokens))
        start += stride
    spans.append((len(ids) - max_tokens, len(ids)))
    return spans


@dataclass
class Scorer:
    backend: Backend
    max_tokens: int = 512
    stride: int = 256
    batch_size: int = 16

    def score(self, text: str) -> dict:
        start = time.perf_counter()
        ids = self.backend.encode(text)
        spans = windows(ids, self.max_tokens, self.stride)
        chunks = [self.backend.decode(ids[a:b]) for a, b in spans]
        probs: list[float] = []
        for i in range(0, len(chunks), self.batch_size):
            probs.extend(self.backend.p_injection(chunks[i:i + self.batch_size]))
        best = max(range(len(probs)), key=probs.__getitem__) if probs else 0
        p = probs[best] if probs else 0.0
        return {"score": p, "label": "INJECTION" if p >= 0.5 else "BENIGN", "windows": len(spans),
                "max_window": best, "model": self.backend.model_name, "revision": self.backend.revision,
                "latency_ms": round((time.perf_counter() - start) * 1000.0, 2)}


class HFBackend:
    """Hugging Face sequence classifier. P(injection) is the softmax mass on whichever label(s)
    the model's own config names as positive, read from id2label rather than assumed."""

    def __init__(self, model_name: str, revision: str = "main", device: str | None = None) -> None:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        self._torch = torch
        self.model_name = model_name
        self.tok = AutoTokenizer.from_pretrained(model_name, revision=revision)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_name, revision=revision)
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device).eval()
        self.revision = getattr(self.model.config, "_commit_hash", None) or revision
        labels = {int(k): str(v).upper() for k, v in self.model.config.id2label.items()}
        self.positive = [i for i, name in labels.items() if name in POSITIVE_LABEL_NAMES or "INJECT" in name]
        if not self.positive:
            raise SystemExit(f"Cannot tell which label of {labels} means injection for {model_name}.")

    def encode(self, text: str) -> list[int]:
        return self.tok(text, add_special_tokens=False)["input_ids"]

    def decode(self, ids: list[int]) -> str:
        return self.tok.decode(ids)

    def p_injection(self, texts: list[str]) -> list[float]:
        torch = self._torch
        with torch.no_grad():
            enc = self.tok(texts, return_tensors="pt", truncation=True, max_length=512, padding=True).to(self.device)
            probs = torch.softmax(self.model(**enc).logits.float(), dim=-1)
            return probs[:, self.positive].sum(dim=-1).tolist()


def make_handler(scorer: Scorer):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, obj: dict) -> None:
            body = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            if self.path == "/health":
                self._send(200, {"status": "ok", "model": scorer.backend.model_name,
                                 "revision": scorer.backend.revision, "max_tokens": scorer.max_tokens,
                                 "stride": scorer.stride})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            if self.path != "/score":
                self._send(404, {"error": "not found"})
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > MAX_BODY_BYTES:
                self._send(413 if length > MAX_BODY_BYTES else 400, {"error": "body missing or too large"})
                return
            try:
                text = json.loads(self.rfile.read(length))["inputs"]
                if not isinstance(text, str):
                    raise TypeError("inputs must be a string")
            except (ValueError, KeyError, TypeError) as exc:
                self._send(400, {"error": f"expected {{\"inputs\": str}}: {exc}"})
                return
            self._send(200, scorer.score(text))

        def log_message(self, *args):  # keep experiment logs clean
            pass

    return Handler


def serve(scorer: Scorer, host: str, port: int) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), make_handler(scorer))


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--model", default="meta-llama/Llama-Prompt-Guard-2-86M")
    p.add_argument("--revision", default="main")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8001)
    p.add_argument("--max-tokens", type=int, default=512)
    p.add_argument("--stride", type=int, default=256)
    args = p.parse_args()
    scorer = Scorer(HFBackend(args.model, args.revision), max_tokens=args.max_tokens, stride=args.stride)
    server = serve(scorer, args.host, args.port)
    print(f"classifier service: {scorer.backend.model_name} @ {scorer.backend.revision} on http://{args.host}:{args.port}/score", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
