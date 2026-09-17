PY := .venv/bin/python
PIP := .venv/bin/pip

.DEFAULT_GOAL := help
.PHONY: help setup test demo pipeline clean dashboard reports evaluate lint-config

help:  ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.venv:
	python3 -m venv .venv
	$(PIP) install --quiet --upgrade pip
	$(PIP) install --quiet -r requirements-dev.txt

setup: .venv  ## create the virtualenv and install test dependencies

test: setup  ## run the test suite
	$(PY) -m pytest -q

demo: setup  ## full demo: tests, then the whole pipeline
	./run_demo.sh

pipeline: setup  ## run the detection pipeline end to end
	$(PY) -m loginwatch run-all

dashboard: setup  ## rebuild the HTML dashboard from the existing database
	$(PY) -m loginwatch dashboard

reports: setup  ## rewrite the incident reports from the existing database
	$(PY) -m loginwatch report

evaluate: setup  ## score detections against ground truth
	$(PY) -m loginwatch evaluate

clean:  ## remove generated data, reports and caches
	rm -rf data reports .pytest_cache
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
