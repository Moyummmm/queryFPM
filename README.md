# QueryFPM

QueryFPM separates a language model's semantic judgment from the authority to
suppress a static-analysis alert. The model proposes TP, FP, or UNKNOWN and may
request one allow-listed analysis action from a CodeQL template menu. The
controller owns query parameters and execution, and an FP proposal is
authorized only when a typed safety certificate, bound to the current alert's
CWE and file/line/column, is established from controller-owned backend rows
with recorded provenance (policy version `explicit-bound-v3`). Confidence is
neither requested from the model nor read by the policy; nearby API calls,
positive query rows, and checked absence authorize nothing; unverified TP
proposals remain UNKNOWN and are retained.

The implementation is intentionally lightweight and reproducible: Python
standard library only, JSONL artifacts, and no API keys in files. The
accompanying paper evaluates it on the OWASP Benchmark Java corpus with a
locally served open-weight model (llama.cpp, OpenAI-compatible endpoint; see
`configs/` for the request settings used by the client).

## What Is Included

- Bounded adjudication loop with controller-owned acquisition and provenance
  hashes (`src/fpm_benchmark/revision_runner.py`, `revision_cli.py`)
- Versioned authorization policy, deterministic per-template result
  interpreters, and exact alert binding (`src/fpm_benchmark/authorization.py`)
- Prompt contract without a confidence field (`revision_prompts.py`) and
  revision run statistics (`revision_statistics.py`)
- CodeQL template manifest, renderer, and batch executor for Java and Python
  templates (`templates/`, `codeql.py`, `batch_codeql.py`)
- `SARIF -> structured evidence` parsing and OWASP Benchmark
  `expectedresults-1.2.csv` alignment
- Operational and selective metrics (`metrics.py`); 61 unit tests (`tests/`)
- The original scaffold CLI (`cli.py`) for the earlier experiment flow

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

If this machine does not have `pip`, use the package without installation:

```bash
export PYTHONPATH="$PWD/src"
python3 -m fpm_benchmark.cli --help
```

Set your API key through the environment variable named in the config
(`DEEPSEEK_API_KEY` in the shipped configs; any placeholder value works for a
local OpenAI-compatible endpoint):

```bash
export DEEPSEEK_API_KEY="your-key"
```

Do not put a real key in `.env.example` or commit it.

## Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Running the Revised Pipeline

```bash
PYTHONPATH=src python3 -m fpm_benchmark.revision_cli run \
  --config configs/<your-config>.json \
  --input <evidence.jsonl> \
  --out <decisions.jsonl> \
  --method queryfpm --budget 2 --guidance generic
```

Configs live in `configs/`; copy one and set `database`, `llm.base_url`,
`llm.model`, and `workers` for the local environment. A full-pipeline run
requires a finalized CodeQL database; every recorded decision carries the
policy version, raw proposal, prompt hash, backend rows, the single
authorization route, and supporting fact identifiers, and a resumed run is
accepted only when the frozen fingerprints match.

## Tooling Check

```bash
scripts/check_env.sh
```

This project can download CodeQL CLI and BenchmarkJava locally:

```bash
scripts/bootstrap_local_toolchain.sh
scripts/bootstrap_assets.sh
export PATH="$PWD/codeql-home/codeql:$PATH"
```

You still need a working Java JDK and Maven to build OWASP Benchmark Java and
create the CodeQL database. On Ubuntu-like systems, the missing system pieces
are typically:

```bash
sudo apt-get update
sudo apt-get install -y openjdk-17-jdk maven unzip
```

## Expected Workflow

1. Prepare OWASP Benchmark Java v1.2 and CodeQL CLI.
2. Create a CodeQL database and run the default Java query suite.
3. Parse CodeQL SARIF into structured evidence.
4. Run the revised adjudication loop (or the earlier scaffold's one-shot /
   iterative triage) against a model endpoint.
5. Evaluate against OWASP ground truth.

Example commands for the scaffold flow:

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

Without installation, replace `fpm-bench` with:

```bash
PYTHONPATH=src python3 -m fpm_benchmark.cli
```

## Main Metrics

- `Precision`: kept alerts that are real vulnerabilities.
- `TP Retention`: original CodeQL true positives retained after triage.
- `FP Reduction`: original CodeQL false positives filtered out.
- `F1`: harmonic mean of Precision and TP Retention.
- `MCC`: balanced binary classification quality.
- `Unknown Rate`: abstained alerts.
- `Selective Accuracy`: accuracy on non-Unknown decisions.

See [docs/experiment_protocol.md](docs/experiment_protocol.md) for the full
experimental design.

## Earlier Frozen Experiment (Hosted Model)

The earlier `experiment-v1` method and artifact identifiers are documented in
[docs/experiment_v1.md](docs/experiment_v1.md). Its hosted-model runner remains
for reference:

```bash
WORKERS=8 ./scripts/run_owasp_1974_deepseek.sh
```

Use a lower worker count if the provider returns HTTP 429 responses. A valid
run must finish with zero LLM and CodeQL infrastructure failures.
