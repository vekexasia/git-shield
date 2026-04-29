# Model evaluation notes

Small local smoke evaluation for PII detectors we may use in the Git hook.

Fixture file:

```text
examples/eval/pii_cases.jsonl
```

Runner:

```text
examples/eval_models.py
```

The fixture is intentionally small and code-oriented. It checks obvious leaks, contextual PII, allowlisted public/test values, and false positives in code placeholders. Treat these numbers as directional only, not benchmark-quality metrics.

## Commands

```bash
# Regex baseline
examples/eval_models.py --backend regex --show-passes

# OpenAI Privacy Filter
examples/eval_models.py --backend opf --device cuda --timeout 300 --show-passes

# NVIDIA GLiNER PII
uv run --with gliner --with torch --python 3.12 \
  examples/eval_models.py --backend gliner --show-passes

# Generic Hugging Face token-classification model
uv run --with transformers --with torch --python 3.12 \
  examples/eval_models.py --backend hf-token \
  --hf-model yonigo/distilbert-base-multilingual-cased-pii \
  --show-passes
```

## Results

| Backend | Model | Precision | Recall | F1 | Time | Notes |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| OPF | `openai/privacy-filter` via `opf` CLI | 0.857 | 0.750 | 0.800 | ~21s | Best precision. Missed secret/API-key case. False-positive on placeholder phone in code. |
| GLiNER | `nvidia/gliner-pii` | 0.700 | 0.875 | 0.778 | ~3.1s | Better recall. Caught secret/API-key. More false positives. |
| HF token | `Dharma20/bert-finetuned-ner-pii-masking-300k` | 0.600 | 0.750 | 0.667 | ~0.3s | Fast/small. Noisy on public/code examples. |
| HF token | `Dharma20/bert-finetuned-pii-masking-300k-accelerate` | 0.500 | 0.500 | 0.500 | ~0.3s | Weaker than the non-accelerate Dharma20 model. |
| Regex | Local regex baseline | 0.667 | 0.250 | 0.364 | ~0s | Fast and simple. Misses contextual PII. |
| HF token | `yonigo/distilbert-base-multilingual-cased-pii` | 0.400 | 0.250 | 0.308 | ~0.3s | Fast, but only caught email/phone reliably in this fixture. |

## Model notes

### `openai/privacy-filter`

Source:

```text
https://huggingface.co/openai/privacy-filter
https://github.com/openai/privacy-filter
```

Pros:

- Apache-2.0.
- Local CLI works with CUDA.
- Good precision on our code-oriented fixture.
- Native labels align with our hook labels: `private_email`, `private_phone`, `private_person`, `secret`, `private_address`, `private_url`, `private_date`, `account_number`.

Cons:

- Heavy model download, about 2.7GB in `~/.opf/privacy_filter`.
- Slower than GLiNER/HF token classifiers on single short examples.
- Missed the synthetic API-key/secret case in the fixture.
- Needs stdin invocation from our adapter. Passing diff chunks as argv can crash with embedded null bytes.

Current status: installed and used by the global pre-push hook.

### `nvidia/gliner-pii`

Source:

```text
https://huggingface.co/nvidia/gliner-pii
```

Model card claims:

- 55+ PII/PHI categories.
- NVIDIA Open Model License Agreement.
- Strict F1 reported by NVIDIA:
  - Argilla PII: 0.70
  - AI4Privacy: 0.64
  - nvidia/Nemotron-PII: 0.87
- Uses `threshold=0.3` in their reported evaluation.

Pros:

- Good recall on our fixture.
- Caught the secret/API-key case OPF missed.
- Faster than OPF in this small local smoke test.
- Flexible labels.

Cons:

- More false positives in our fixture.
- Needs GLiNER dependency and label mapping.
- License is NVIDIA Open Model License Agreement, not Apache/MIT.

Potential use: secondary backend or experimental alternative if recall matters more than precision.

### `ai4privacy/pii-masking-300k`

Source:

```text
https://huggingface.co/datasets/ai4privacy/pii-masking-300k
```

This is a dataset, not a detector model.

Notes:

- Gated dataset on Hugging Face.
- Custom/other license. Commercial use requires contacting `licensing@ai4privacy.com`.
- Languages: English, French, German, Italian, Spanish, Dutch.
- OpenPII-220k has 27 PII classes; FinPII adds finance/insurance classes.
- Rows include `source_text`, `target_text`, `privacy_mask`, `span_labels`, and BIO labels.

Useful as training/eval data, but licensing/access make it less convenient for a default hook dependency.

### `Dharma20/bert-finetuned-ner-pii-masking-300k`

Source:

```text
https://huggingface.co/Dharma20/bert-finetuned-ner-pii-masking-300k
```

Pros:

- Small, around 0.1B params.
- Fast local inference.
- Labels match the AI4Privacy taxonomy.

Cons:

- Empty model card, no metrics/licensing details found.
- Noisy on public/code examples in our fixture.
- Worse F1 than OPF/GLiNER.

### `Dharma20/bert-finetuned-pii-masking-300k-accelerate`

Source:

```text
https://huggingface.co/Dharma20/bert-finetuned-pii-masking-300k-accelerate
```

Same caveats as the other Dharma20 model, with weaker fixture results.

### `yonigo/distilbert-base-multilingual-cased-pii`

Source:

```text
https://huggingface.co/yonigo/distilbert-base-multilingual-cased-pii
```

Model card claims:

- Fine-tuned from `distilbert-base-multilingual-cased` on `ai4privacy/pii-masking-300k`.
- Reported eval: precision 0.9428, recall 0.9582, F1 0.9504, accuracy 0.9909.

Pros:

- Fast and small.
- Public model card with metrics.
- Training code linked from the card.

Cons:

- Poor result on our fixture.
- Only caught email/phone reliably in the smoke test.
- Missed contextual person/address/date/secret cases.
- False positives on some public/test/code examples.

## Current recommendation

Keep OPF as the default global pre-push backend for now.

Reasons:

- Best precision on the local fixture.
- Native labels match the project.
- Already installed and smoke-tested.
- License is straightforward.

Potential follow-up:

- Add GLiNER as an optional backend for comparison or a recall-oriented mode.
- Expand fixtures with real code diffs from target repos, especially `risto-menu`.
- Add file/path reporting to whole-repo scans.
- Add ignore rules for `.pii-allowlist`, test fixtures, and obvious placeholder values when scanning full repositories.
