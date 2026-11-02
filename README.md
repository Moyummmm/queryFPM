# QueryFPM

QueryFPM separates a language model's semantic judgment from the authority to
suppress a static-analysis alert. The model proposes TP, FP, or UNKNOWN and may
request one allow-listed CodeQL analysis action. The controller owns query
parameters and execution, and an FP proposal is authorized only when a typed
safety certificate bound to the current alert is established from
controller-owned backend rows with recorded provenance. Confidence is never
read by the policy; unverified TP proposals remain UNKNOWN and are retained.

The implementation is Python standard library only, with JSONL artifacts and no
API keys in files. It is evaluated on the OWASP Benchmark Java corpus with a
locally served open-weight model (llama.cpp, OpenAI-compatible endpoint).

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Without `pip`, run from the source tree:

```bash
export PYTHONPATH="$PWD/src"
python3 -m fpm_benchmark.cli --help
```

API keys come from the environment variable named in the config
(`DEEPSEEK_API_KEY` in the shipped configs; any placeholder value works for a
local OpenAI-compatible endpoint):

```bash
export DEEPSEEK_API_KEY="your-key"
```

## Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Running the Pipeline

Revised adjudication loop:

```bash
PYTHONPATH=src python3 -m fpm_benchmark.revision_cli run \
  --config configs/<your-config>.json \
  --input <evidence.jsonl> \
  --out <decisions.jsonl> \
  --method queryfpm --budget 2 --guidance generic
```

Scaffold flow (`parse-sarif` -> `llm-triage` -> `evaluate`):

```bash
fpm-bench parse-sarif \
  --sarif data/raw/codeql-default.sarif \
  --expected BenchmarkJava/expectedresults-1.2.csv \
  --source-root BenchmarkJava \
  --out data/interim/evidence.jsonl

fpm-bench llm-triage \
  --input data/interim/evidence.jsonl \
  --out data/results/decisions.jsonl \
  --config configs/experiment.json \
  --mode one-shot \
  --view structured

fpm-bench evaluate \
  --decisions data/results/decisions.jsonl \
  --out data/results/metrics.json
```

Without installation, replace `fpm-bench` with
`PYTHONPATH=src python3 -m fpm_benchmark.cli`.

## Tooling

```bash
scripts/check_env.sh
scripts/bootstrap_local_toolchain.sh
scripts/bootstrap_assets.sh
export PATH="$PWD/codeql-home/codeql:$PATH"
```

A working Java 17 JDK and Maven are required to build OWASP Benchmark Java and
create the CodeQL database.
