# Model scan (supply chain)

The `model-scan` command inspects **local** model artifacts (`.pkl`, `.pickle`, `.pt`, `.pth`, `.bin`, `.onnx`, `.safetensors`, `.gguf`, `.pb`, `.h5`, `.keras`) for deserialization and format risks. It emits standard `report.Finding` JSON like other modules.

## Usage

```bash
aipostex model-scan --path /path/to/model.pt --format json
aipostex model-scan --path /data/models/ --format json
aipostex model-scan --path /data/models/ --max-file-size-mb 0 --exclude custom_vendor
aipostex model-scan --path ./weights.bin --hash sha256:<hex>
```

## Flags

| Flag | Description |
|------|-------------|
| `--path` | File or directory (required). |
| `--hash` | For a **single file**, compare SHA-256 to `sha256:hex` (tamper check). |
| `--max-file-size-mb` | Directory scans only: skip files larger than this (default `100`). Use `0` for no limit. |
| `--exclude` | Extra directory **base names** to skip during directory walks (merged with built-in vendor paths). |
| `--no-default-excludes` | Do not skip `.git`, `node_modules`, `venv`, etc.; only `--exclude` entries apply. |

## Risk types (examples)

| Risk type | Severity | Meaning |
|-----------|----------|---------|
| `pickle-deserialization` | critical | Pickle can execute code on load. |
| `pytorch-pickle` | critical | `torch.save` ZIP+pickle checkpoint — unsafe `torch.load()` defaults. |
| `pickle-opcode-*` | critical | Dangerous opcode observed in scanned bytes. |
| `tf-python-op` | critical | TensorFlow SavedModel `.pb` containing a Python function op — arbitrary code execution on load. |
| `keras-lambda-layer` | high | `.h5` or `.keras` model with a Lambda layer — serialized Python source executed on load. |
| `onnx-custom-op` | high | ONNX model references a custom operator domain — may load untrusted native code. |
| `onnx-external-data` | medium | ONNX model references external tensor data files — path traversal / supply-chain risk. |
| `model-format` | info | ONNX, SafeTensors, GGUF, `.pb` (no Python ops), `.h5`/`.keras` (no Lambda) — note format / provenance. |
| `skipped-large-file` | info | File over `--max-file-size-mb` during directory scan. |

## What each `landed` level means here

Findings carry a `landed` axis recording what actually landed on a target. `model-scan` is a local, static scanner: it reads and classifies files on your own filesystem, so nothing lands on a remote target and every finding sits at the floor.

| `landed` | What produces it in model-scan |
|---|---|
| `reachable` | Every risk finding — the file was read and statically classified (pickle/PyTorch surface, dangerous opcode, ONNX/TF/Keras execution surface, `--hash` result). No code was run and no remote target was touched. |

Ceiling: `reachable`. Severity still reflects real danger (e.g. `pickle-deserialization` is `critical`), but static inspection alone never processes input on, reads from, or executes on a target, so the higher `landed` levels do not apply.

## Implementation

Logic lives in [`pkg/modelscan`](https://github.com/professor-moody/aipostex/tree/main/pkg/modelscan); CLI in `cmd/aipostex/model_scan.go`.
