#!/usr/bin/env bash
set -euo pipefail

TIMEOUT_SECONDS="${NETNS_TEST_TIMEOUT_SECONDS:-90}"
# The twin scenarios wait out real sender timers the other targets never touch —
# the 15s ACK liveness timeout and the 30s status-log interval — so they cannot
# share the default budget.
TWIN_TIMEOUT_SECONDS="${NETNS_TWIN_TEST_TIMEOUT_SECONDS:-420}"
for BUDGET in "${TIMEOUT_SECONDS}" "${TWIN_TIMEOUT_SECONDS}"; do
  [[ "${BUDGET}" =~ ^[1-9][0-9]*$ ]] || {
    echo "netns-test-gate: timeout budgets must be positive integers" >&2
    exit 2
  }
done

ALL_TARGETS=(
  netns_basic
  netns_family
  netns_failure
  netns_impairment
  netns_scenario
  netns_stall_gate
  netns_twin
  netns_wire_loss
)

ONLY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --only)
      ONLY="${2:-}"
      [[ -n "${ONLY}" ]] || {
        echo "netns-test-gate: --only requires a target name" >&2
        exit 2
      }
      shift 2
      ;;
    *)
      echo "netns-test-gate: unknown argument '$1'" >&2
      exit 2
      ;;
  esac
done

TARGETS=()
if [[ -n "${ONLY}" ]]; then
  for TARGET in "${ALL_TARGETS[@]}"; do
    [[ "${TARGET}" == "${ONLY}" ]] && TARGETS=("${TARGET}")
  done
  [[ "${#TARGETS[@]}" -gt 0 ]] || {
    echo "netns-test-gate: '${ONLY}' is not a registered target" >&2
    exit 2
  }
else
  TARGETS=("${ALL_TARGETS[@]}")
fi

budget_for() {
  case "$1" in
    netns_family) echo "180" ;;
    netns_twin) echo "${TWIN_TIMEOUT_SECONDS}" ;;
    *) echo "${TIMEOUT_SECONDS}" ;;
  esac
}

for TARGET in "${TARGETS[@]}"; do
  BUDGET="$(budget_for "${TARGET}")"
  CARGO_ARGS=()
  TEST_ARGS=(--nocapture)
  if [[ "${TARGET}" == netns_family ]]; then
    CARGO_ARGS=(-j1)
    TEST_ARGS+=(--test-threads=1)
  fi
  set +e
  timeout --foreground --kill-after=10s "${BUDGET}s" \
    cargo test "${CARGO_ARGS[@]}" --all-features --test "${TARGET}" -- "${TEST_ARGS[@]}"
  STATUS=$?
  set -e
  if [[ "${STATUS}" -eq 124 ]]; then
    echo "netns-test-gate: ${TARGET} exceeded ${BUDGET}s" >&2
    exit 124
  fi
  [[ "${STATUS}" -eq 0 ]] || exit "${STATUS}"
done

echo "netns-test-gate: OK timeout=${TIMEOUT_SECONDS}s twin-timeout=${TWIN_TIMEOUT_SECONDS}s targets=${#TARGETS[@]}"
