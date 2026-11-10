"""Abliterate an open-weight attacker model (refusal-direction ablation, Arditi et al., 2024).

STATUS: written and statically checked, NOT YET EXECUTED. It needs a GPU runtime (Kaggle/Colab
T4 or better) and the model weights from Hugging Face, neither of which the team's dev laptops
or the CI container has. Nothing in the workbook reports a result from this script until a run
log exists under results/abliteration/.

Why the team does this itself (decided in WB1): a downloaded "uncensored" model is an unknown
artifact (unknown method, data and revision). Doing it ourselves pins every one of those, and the
refusal rate before/after becomes a measured number in the manifest instead of a claim.

Method (Arditi et al., "Refusal in Language Models Is Mediated by a Single Direction", 2024):
  1. Run N "refused" instructions and N "ordinary" instructions through the model; record the
     residual-stream activation at the last prompt token at every layer.
  2. Candidate direction per layer: r_l = mean(refused) - mean(ordinary), normalised.
  3. Choose the layer whose direction, when ablated, most reduces refusals on a held-out set while
     the model still writes fluent text (we score refusal with the same REFUSAL_MARKERS the
     harness uses, so "refusal" means the same thing here as in the experiment).
  4. Orthogonalise every weight matrix that writes into the residual stream against r:
       W <- W - r r^T W   (attention o_proj and MLP down_proj, shape [d_model, *])
       E <- E - (E r) r^T (token embeddings, rows are d_model vectors)
     so the model can no longer represent the refusal direction; no fine-tuning involved.
  5. Save the edited model, then convert to GGUF and import into Ollama (commands printed at the end).

Prompt sets are NOT bundled. Pass them as text files with one instruction per line, e.g. the
public AdvBench harmful_behaviors and an equal-sized Alpaca sample. Our use: the abliterated model
only ever writes injection text for a synthetic sandbox; it is never exposed to anyone else.

Usage (on a GPU runtime):
  pip install torch transformers accelerate
  python scripts/abliterate.py --model Qwen/Qwen2.5-7B-Instruct --refused refused.txt \
      --ordinary ordinary.txt --out results/abliteration/qwen2.5-7b-abliterated --n 128
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rtbt.attackers.local_model import looks_like_refusal  # noqa: E402  same refusal test as the harness


def read_lines(path: str) -> list[str]:
    return [ln.strip() for ln in Path(path).read_text(encoding="utf-8").splitlines() if ln.strip()]


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--model", required=True, help="Hugging Face id of an instruct model.")
    p.add_argument("--revision", default="main", help="Pin a commit hash for reproducibility.")
    p.add_argument("--refused", required=True, help="Text file: one instruction the model refuses per line.")
    p.add_argument("--ordinary", required=True, help="Text file: one ordinary instruction per line.")
    p.add_argument("--out", required=True)
    p.add_argument("--n", type=int, default=128, help="Prompts per set used to estimate the direction.")
    p.add_argument("--eval-n", type=int, default=32, help="Held-out refused prompts used to pick the layer.")
    p.add_argument("--layers", default="", help="Comma list of layers to try (default: middle 40%% of the stack).")
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args()

    import torch  # imported here so `--help` works without a GPU stack installed
    from transformers import AutoModelForCausalLM, AutoTokenizer

    random.seed(args.seed)
    torch.manual_seed(args.seed)
    refused, ordinary = read_lines(args.refused), read_lines(args.ordinary)
    random.shuffle(refused)
    random.shuffle(ordinary)
    fit_refused, eval_refused = refused[: args.n], refused[args.n: args.n + args.eval_n]
    fit_ordinary = ordinary[: args.n]
    if len(fit_refused) < args.n or len(fit_ordinary) < args.n or len(eval_refused) < args.eval_n:
        raise SystemExit("Not enough prompts for --n/--eval-n.")

    tok = AutoTokenizer.from_pretrained(args.model, revision=args.revision)
    model = AutoModelForCausalLM.from_pretrained(args.model, revision=args.revision,
                                                 torch_dtype=torch.float16, device_map="auto")
    model.eval()
    layers = model.model.layers
    n_layers = len(layers)

    def chat(text: str) -> str:
        return tok.apply_chat_template([{"role": "user", "content": text}], tokenize=False, add_generation_prompt=True)

    @torch.no_grad()
    def last_token_resid(prompts: list[str]) -> torch.Tensor:
        """[n_layers+1, d_model] mean residual stream at the final prompt token."""
        total = None
        for prompt in prompts:
            ids = tok(chat(prompt), return_tensors="pt").to(model.device)
            hs = model(**ids, output_hidden_states=True).hidden_states  # tuple of [1, seq, d]
            vec = torch.stack([h[0, -1].float() for h in hs])
            total = vec if total is None else total + vec
        return total / len(prompts)

    @torch.no_grad()
    def refusal_rate(prompts: list[str]) -> float:
        refusals = 0
        for prompt in prompts:
            ids = tok(chat(prompt), return_tensors="pt").to(model.device)
            out = model.generate(**ids, max_new_tokens=48, do_sample=False)
            refusals += looks_like_refusal(tok.decode(out[0, ids["input_ids"].shape[1]:], skip_special_tokens=True))
        return refusals / len(prompts)

    t0 = time.time()
    diff = last_token_resid(fit_refused) - last_token_resid(fit_ordinary)  # [n_layers+1, d]
    candidates = ([int(x) for x in args.layers.split(",")] if args.layers
                  else list(range(int(n_layers * 0.3), int(n_layers * 0.7) + 1)))
    baseline_refusal = refusal_rate(eval_refused)
    print(f"baseline refusal rate on held-out set: {baseline_refusal:.3f}")

    def hook_for(r: torch.Tensor):
        # Inference-time ablation used only to SCORE a candidate: x <- x - (x.r) r at every layer.
        def hook(_module, _inputs, output):
            h = output[0] if isinstance(output, tuple) else output
            h = h - (h.float() @ r).unsqueeze(-1).to(h.dtype) * r.to(h.dtype)
            return (h, *output[1:]) if isinstance(output, tuple) else h
        return hook

    scores = {}
    for layer in candidates:
        r = diff[layer] / diff[layer].norm()
        r = r.to(model.device)
        handles = [blk.register_forward_hook(hook_for(r)) for blk in layers]
        try:
            scores[layer] = refusal_rate(eval_refused)
        finally:
            for h in handles:
                h.remove()
        print(f"layer {layer:>3}: refusal rate with direction ablated = {scores[layer]:.3f}")
    best = min(scores, key=scores.get)
    r = (diff[best] / diff[best].norm()).to(model.device)

    # Permanent edit: orthogonalise every matrix that writes to the residual stream.
    with torch.no_grad():
        emb = model.model.embed_tokens.weight
        emb -= ((emb.float() @ r).unsqueeze(-1) * r).to(emb.dtype)
        for blk in layers:
            for W in (blk.self_attn.o_proj.weight, blk.mlp.down_proj.weight):  # [d_model, *]
                W -= (r.unsqueeze(-1) @ (r.unsqueeze(0) @ W.float())).to(W.dtype)
    after = refusal_rate(eval_refused)
    print(f"chosen layer {best}; refusal rate after weight edit = {after:.3f} (before {baseline_refusal:.3f})")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(out)
    tok.save_pretrained(out)
    log = {"method": "refusal-direction weight orthogonalisation (Arditi et al., 2024)", "model": args.model,
           "revision": args.revision, "seed": args.seed, "n_fit_per_set": args.n, "n_eval": args.eval_n,
           "candidate_layers": candidates, "refusal_rate_by_layer": scores, "chosen_layer": best,
           "refusal_rate_before": baseline_refusal, "refusal_rate_after": after,
           "refusal_detector": "rtbt.attackers.local_model.looks_like_refusal", "seconds": round(time.time() - t0, 1)}
    (out / "abliteration_log.json").write_text(json.dumps(log, indent=2), encoding="utf-8")
    print(json.dumps(log, indent=2))
    print("\nNext, convert and import into Ollama (llama.cpp checkout required):\n"
          f"  python llama.cpp/convert_hf_to_gguf.py {out} --outfile {out}.gguf --outtype q8_0\n"
          f"  printf 'FROM ./{out.name}.gguf\\n' > Modelfile && ollama create {out.name} -f Modelfile\n"
          "Then set model_config.abliterated=true and model_config.revision to the base revision above.")


if __name__ == "__main__":
    main()
