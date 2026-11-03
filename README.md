# QueryFPM

## Quick start

Use Python 3.11 or later. Running the full pipeline also requires a CodeQL
database, the CodeQL CLI, an OpenAI-compatible model endpoint, and an input
evidence JSONL file bound to that database.

Create an environment and install the package:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

On Windows PowerShell, activate the environment with
`.\.venv\Scripts\Activate.ps1` instead.

Create a revision-run configuration with the CodeQL manifest, database,
executable, and model endpoint. Set the API key in the environment variable
named by `llm.api_key_env` in that configuration. Replace the paths below with
your configuration, evidence, and output paths:

```bash
python -m fpm_benchmark.revision_cli run \
  --config path/to/revision-config.json \
  --input path/to/evidence.jsonl \
  --out path/to/decisions.jsonl \
  --method queryfpm --budget 2 --guidance generic
```
