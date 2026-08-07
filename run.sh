#!/usr/bin/env bash
# JMD Security Suite dispatcher.
#   ./run.sh setup          install deps into .venv
#   ./run.sh test           run all test suites
#   ./run.sh data           (re)generate datasets/corpora
#   ./run.sh train          train the LinkGuard ML URL classifier (writes the model)
#   ./run.sh web            launch the interactive WEBSITE + API (open http://localhost:8000)
#   ./run.sh eval           measure ACCURACY of all 5 tools against labelled cases
#   ./run.sh holdout        held-out generalisation check (never tuned against)
#   ./run.sh fuzz           robustness: hostile input must never crash a tool
#   ./run.sh console        launch the unified PREMIUM console (Streamlit, all 4 tools)
#   ./run.sh api            launch the unified REST API (FastAPI; also serves the website)
#   ./run.sh resumeshield   launch ResumeShield dashboard
#   ./run.sh siteguard      launch SiteGuard dashboard
#   ./run.sh linkguard      launch LinkGuard dashboard
#   ./run.sh breachradar    launch BreachRadar dashboard
#   ./run.sh docker         build the image and run the website+API on :8000
#   ./run.sh demo           run a quick CLI demo of all four tools
set -euo pipefail
cd "$(dirname "$0")"
PY=./.venv/bin/python
ST=./.venv/bin/streamlit
UV=./.venv/bin/uvicorn

case "${1:-help}" in
  setup)
    [ -d .venv ] || python3 -m venv .venv
    ./.venv/bin/pip install --upgrade pip >/dev/null
    ./.venv/bin/pip install -r requirements.txt
    ;;
  data)
    $PY breachradar/data/generate_breaches.py
    ;;
  test)
    $PY resumeshield/tests/test_pii.py
    $PY siteguard/tests/test_scanner.py
    $PY linkguard/tests/test_engine.py
    $PY linkguard/tests/test_model.py
    $PY siteguard/tests/test_netguard.py
    $PY breachradar/tests/test_engine.py
    $PY breachradar/tests/test_live.py
    $PY api/tests/test_security.py
    $PY tests/test_integration.py
    ;;
  train)
    $PY -c "from linkguard.model import train; m=train(); print('LinkGuard URL model:', {k:m[k] for k in ('accuracy','precision','recall','f1','roc_auc')})"
    ;;
  docker)
    docker build -t jmd-security-suite . && \
    echo "→ Website:  http://localhost:8000" && \
    docker run --rm -p 8000:8000 jmd-security-suite
    ;;
  eval)         $PY eval/run_eval.py "$@" ;;
  holdout)      $PY eval/holdout.py ;;
  fuzz)         $PY eval/robustness.py ;;
  console)      $ST run console/app.py ;;
  web|api)      echo "→ Website:  http://localhost:8000" && echo "→ API docs: http://localhost:8000/docs" && $UV api.main:app --port 8000 ;;
  resumeshield) $ST run resumeshield/app.py ;;
  siteguard)    $ST run siteguard/app.py ;;
  linkguard)    $ST run linkguard/app.py ;;
  breachradar)  $ST run breachradar/app.py ;;
  demo)
    echo "== ResumeShield =="; $PY -m resumeshield.redact
    echo; echo "== SiteGuard (vulnerable demo) =="; $PY -m siteguard.cli --demo vulnerable
    echo; echo "== LinkGuard (sample links) =="; $PY -m linkguard.cli demo
    echo; echo "== BreachRadar (org scan) =="; $PY -m breachradar.cli scan-org
    ;;
  *)
    grep '^#' "$0" | sed 's/^# \{0,1\}//'
    ;;
esac
