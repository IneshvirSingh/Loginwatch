#!/usr/bin/env bash
#
# One-command demo: sets up the environment, runs the tests, then runs the
# whole detection pipeline end to end and tells you what to look at.
#
#   ./run_demo.sh
#
# Everything runs locally and offline. No API key, no network, no real data.

set -euo pipefail

cd "$(dirname "$0")"

VENV=".venv"
PYTHON="${PYTHON:-python3}"

banner() {
    printf '\n\033[1m%s\033[0m\n' "$1"
    printf '%s\n' "------------------------------------------------------------------------"
}

# --- 1. environment -------------------------------------------------------
# The project itself needs only the Python standard library. The virtualenv
# exists so that pytest can be installed without touching the system Python.
if [ ! -d "$VENV" ]; then
    banner "Creating virtual environment ($VENV)"
    "$PYTHON" -m venv "$VENV"
fi

PY="$VENV/bin/python"

if ! "$PY" -c "import pytest" >/dev/null 2>&1; then
    banner "Installing test dependencies"
    "$PY" -m pip install --quiet --upgrade pip
    "$PY" -m pip install --quiet -r requirements-dev.txt
fi

# --- 2. tests -------------------------------------------------------------
banner "Running the test suite"
"$PY" -m pytest -q

# --- 3. pipeline ----------------------------------------------------------
banner "Running the full pipeline"
"$PY" -m loginwatch run-all

# --- 4. what to do next ---------------------------------------------------
banner "Where to look"
cat <<'EOF'
  reports/dashboard.html      summary dashboard (open it in a browser)
  reports/incident-*.md       analyst write-ups of the top incidents
  data/raw/auth.log           the synthetic log that was analysed
  data/raw/ground_truth.jsonl the attack labels used to score detection

  Explore from the command line:
    .venv/bin/python -m loginwatch incidents
    .venv/bin/python -m loginwatch incident-show <id>
    .venv/bin/python -m loginwatch alerts --severity critical
    .venv/bin/python -m loginwatch alert-show <id>
    .venv/bin/python -m loginwatch evaluate
    .venv/bin/python -m loginwatch ai-triage <alert-id> --show-prompt

  Everything above is synthetic data. No real system was touched.
EOF
