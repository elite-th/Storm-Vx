#!/usr/bin/env bash
# Storm-VX CI Validation Script — W5.5
# Run all CI checks locally — mirrors .github/workflows/ci.yml
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass=0
fail=0

run_check() {
    local name="$1"
    shift
    echo ""
    echo -e "${YELLOW}=== ${name} ===${NC}"
    if "$@"; then
        echo -e "${GREEN}PASS: ${name}${NC}"
        ((pass++))
    else
        echo -e "${RED}FAIL: ${name}${NC}"
        ((fail++))
    fi
}

check_lint() {
    if command -v ruff &> /dev/null; then
        ruff check --config pyproject.toml . --exclude tests
    else
        echo "ruff not installed - skipping"
        return 0
    fi
}

check_types() {
    if command -v mypy &> /dev/null; then
        mypy --config-file pyproject.toml finder/ tester/ evasion/ config/ utils/ observability/ --no-error-summary 2>/dev/null || true
        echo "(mypy is informational)"
        return 0
    else
        echo "mypy not installed - skipping"
        return 0
    fi
}

check_security() {
    if command -v bandit &> /dev/null; then
        bandit -r -c pyproject.toml finder/ tester/ evasion/ infra/ config/ utils/ observability/ || true
        echo "(bandit is informational)"
        return 0
    else
        echo "bandit not installed - skipping"
        return 0
    fi
}

check_tests() {
    python -m pytest tests/ --cov=finder --cov=tester --cov=evasion --cov=config --cov=utils --cov=observability --cov-report=term-missing --cov-fail-under=0 -q --tb=short
}

cd "$(dirname "$0")/.."

case "${1:-all}" in
    lint)     run_check "Ruff Lint" check_lint ;;
    type)     run_check "Mypy" check_types ;;
    security) run_check "Bandit" check_security ;;
    test)     run_check "Pytest" check_tests ;;
    all)
        run_check "Ruff Lint" check_lint
        run_check "Mypy" check_types
        run_check "Bandit" check_security
        run_check "Pytest" check_tests
        ;;
    *)
        echo "Usage: $0 {lint|type|security|test|all}"
        exit 1
        ;;
esac

echo ""
echo -e "${YELLOW}=== Summary ===${NC}"
echo -e "  Passed: ${pass}"
if [ "$fail" -gt 0 ]; then
    echo -e "  ${RED}Failed: ${fail}${NC}"
    exit 1
else
    echo -e "  Failed: 0"
fi
