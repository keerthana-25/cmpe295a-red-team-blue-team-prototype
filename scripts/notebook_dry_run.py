"""Dry-run notebooks/wb2_baselines.ipynb (steps 5-10) on a laptop, with no GPU and no model.

    python3 scripts/notebook_dry_run.py [GPU_HOURS]

Starts tests/fakes/fake_ollama.py on 127.0.0.1:11434 and the real classifier service with a fake
backend on 127.0.0.1:8001 (both ports must be free), then executes the notebook's own code cells
unchanged. Use it after editing the notebook or the configs it reads. The numbers it prints come
from fakes and mean nothing; only "did every step run" matters.
"""
import json, sys, os, pathlib, threading, subprocess, shutil, time, tempfile
REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO/"src"), str(REPO/"services"), str(REPO/"tests"/"fakes"), str(REPO/"tests")]
import fake_ollama
from classifier_server import Scorer, serve
class Det:
    model_name, revision = "fake/address-detector", "test"
    def encode(self, t): return t.split()
    def decode(self, i): return " ".join(i)
    def p_injection(self, ts): return [0.95 if ("attacker@example.invalid" in t or "IMPORTANT" in t) else 0.02 for t in ts]
o = fake_ollama.serve(11434); c = serve(Scorer(Det()), "127.0.0.1", 8001)
for s in (o, c): threading.Thread(target=s.serve_forever, daemon=True).start()
nb = json.load(open(REPO/"notebooks"/"wb2_baselines.ipynb"))
codes = [ "".join(x["source"]) for x in nb["cells"] if x["cell_type"] == "code"]
OUT = pathlib.Path(tempfile.mkdtemp(prefix="rtbt_nb_dry_"))
g = dict(json=json, os=os, sys=sys, subprocess=subprocess, pathlib=pathlib, shutil=shutil, time=time,
         REPO=REPO, OUT_DIR=OUT, TARGET="fake-ollama", TARGET_DIGEST="sha256:fake0000000000000000",
         HEALTH={"model": "fake/address-detector", "revision": "test"}, COMMIT="local", GPU_HOURS=float(sys.argv[1]) if len(sys.argv) > 1 else 0.05)
for i, src in enumerate(codes[4:], start=5):   # steps 5..10; 1-4 are environment setup replaced above
    print(f"===== cell for step {i}"); exec(src, g)
