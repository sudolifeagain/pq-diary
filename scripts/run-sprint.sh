#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# pq-diary Sprint 自動実装スクリプト
# Usage: bash scripts/run-sprint.sh [START_TASK]
# Example: bash scripts/run-sprint.sh TASK-0004  # TASK-0004 から再開
# =============================================================================

# === 設定 ===
SPRINT_NAME="s8-git-sync"
SPRINT_TAG="s8"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TASKS_DIR="${PROJECT_ROOT}/docs/tasks/${SPRINT_NAME}"
PROMPTS_DIR="$(dirname "$0")/prompts"
LOG_DIR="${PROJECT_ROOT}/logs/sprint-${SPRINT_NAME}"

# タスク一覧 (依存順)
TASKS=(TASK-0074 TASK-0075 TASK-0076 TASK-0077 TASK-0078 TASK-0079)

# タスクタイプ
declare -A TASK_TYPES=(
    [TASK-0074]="TDD"
    [TASK-0075]="TDD"
    [TASK-0076]="TDD"
    [TASK-0077]="TDD"
    [TASK-0078]="TDD"
    [TASK-0079]="TDD"
)

# タスク名 (コミットメッセージ用)
declare -A TASK_NAMES=(
    [TASK-0074]="git foundation check_git_available and git-init"
    [TASK-0075]="privacy helpers author timestamp fuzzing padding"
    [TASK-0076]="git-push with privacy pipeline"
    [TASK-0077]="git-pull and 3-way merge by UUID HMAC"
    [TASK-0078]="CLI git subcommand handlers"
    [TASK-0079]="integration tests doc comments and run-sprint update"
)

# モデル設定
IMPLEMENT_MODEL="${IMPLEMENT_MODEL:-sonnet}"
REVIEW_MODEL="${REVIEW_MODEL:-opus}"
MAX_RETRIES=3
CURRENT_TASK=""

# === ログ ===
log() {
    local level="$1"; shift
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[${ts}] [${level}] $*" | tee -a "${LOG_DIR}/sprint.log"
}
log_info()  { log "INFO"  "$@"; }
log_warn()  { log "WARN"  "$@"; }
log_error() { log "ERROR" "$@"; }
log_ok()    { log " OK  " "$@"; }

# === 進捗表示 ===
show_progress() {
    local current="$1" total="$2" task_id="$3" step="$4"
    echo ""
    echo "============================================"
    echo "  [${current}/${total}] ${task_id} — ${step}"
    echo "============================================"
}

# === 環境チェック ===
check_prerequisites() {
    local missing=()
    command -v claude >/dev/null 2>&1 || missing+=("claude")
    command -v cargo  >/dev/null 2>&1 || missing+=("cargo")
    command -v git    >/dev/null 2>&1 || missing+=("git")

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing: ${missing[*]}"
        exit 1
    fi

    local branch
    branch="$(git branch --show-current)"
    if [[ "${branch}" != "sprint/${SPRINT_TAG}" ]]; then
        log_warn "Expected 'sprint/${SPRINT_TAG}', on '${branch}'"
    fi

    log_ok "Prerequisites OK (claude, cargo, git)"
}

# === テスト実行 ===
run_tests() {
    local label="$1"

    if [[ "${CURRENT_TASK}" == "TASK-0001" ]]; then
        log_info "${label}: cargo build (TASK-0001 — workspace初回)"
        if ! cargo build --workspace >> "${LOG_DIR}/${CURRENT_TASK}_build.log" 2>&1; then
            log_error "${label}: cargo build failed"
            return 1
        fi
        log_ok "${label}: build passed"
        return 0
    fi

    log_info "${label}: cargo test"
    if ! cargo test --workspace >> "${LOG_DIR}/${CURRENT_TASK}_test.log" 2>&1; then
        log_error "${label}: cargo test failed"
        return 1
    fi

    log_info "${label}: cargo clippy"
    if ! cargo clippy --workspace -- -D warnings >> "${LOG_DIR}/${CURRENT_TASK}_clippy.log" 2>&1; then
        log_error "${label}: cargo clippy failed"
        return 1
    fi

    log_info "${label}: cargo fmt --check"
    if ! cargo fmt --check >> "${LOG_DIR}/${CURRENT_TASK}_fmt.log" 2>&1; then
        log_warn "${label}: cargo fmt found issues, auto-fixing"
        cargo fmt >> "${LOG_DIR}/${CURRENT_TASK}_fmt.log" 2>&1
    fi

    log_ok "${label}: all checks passed"
    return 0
}

# === プロンプト展開 ===
expand_prompt() {
    local template_file="$1"
    local task_id="$2"
    local task_type="${TASK_TYPES[$task_id]}"

    sed -e "s/{{TASK_ID}}/${task_id}/g" \
        -e "s/{{TASK_TYPE}}/${task_type}/g" \
        -e "s/{{SPRINT_NAME}}/${SPRINT_NAME}/g" \
        "${template_file}"
}

# === Claude CLI 実行 ===
run_claude() {
    local role="$1"
    local task_id="$2"
    local prompt="$3"
    local model="$4"
    local attempt="${5:-1}"
    local log_file="${LOG_DIR}/${task_id}_${role}_attempt${attempt}.log"

    log_info "[${task_id}] ${role} (model=${model}, attempt ${attempt}/${MAX_RETRIES})"

    if echo "${prompt}" | claude -p \
        --dangerously-skip-permissions \
        --model "${model}" \
        --no-session-persistence \
        --append-system-prompt "You are working on pq-diary (Rust PQC CLI journal). Sprint: ${SPRINT_NAME}. Read CLAUDE.md first for all project rules." \
        > "${log_file}" 2>&1; then
        log_ok "[${task_id}] ${role}: completed"
        return 0
    else
        log_error "[${task_id}] ${role}: failed (exit $?)"
        return 1
    fi
}

# === メイン ===
main() {
    cd "${PROJECT_ROOT}"
    mkdir -p "${LOG_DIR}"

    # .gitignore に logs/ を追加
    if ! grep -q "^logs/" .gitignore 2>/dev/null; then
        echo "logs/" >> .gitignore
    fi

    check_prerequisites

    log_info "Sprint ${SPRINT_NAME} automation started"
    log_info "Implement model: ${IMPLEMENT_MODEL}, Review model: ${REVIEW_MODEL}"

    # 開始タスクの決定
    local start_task="${1:-${TASKS[0]}}"
    local start_idx=0
    for i in "${!TASKS[@]}"; do
        if [[ "${TASKS[$i]}" == "${start_task}" ]]; then
            start_idx=$i
            break
        fi
    done
    log_info "Starting from ${start_task} (index ${start_idx})"

    local total=${#TASKS[@]}

    for i in $(seq "${start_idx}" $((total - 1))); do
        local task_id="${TASKS[$i]}"
        local current=$((i + 1))
        CURRENT_TASK="${task_id}"
        local task_name="${TASK_NAMES[$task_id]}"

        log_info "========== ${task_id}: ${task_name} =========="

        local task_success=false

        for retry in $(seq 1 "${MAX_RETRIES}"); do
            if [[ ${retry} -gt 1 ]]; then
                log_warn "[${task_id}] Retry ${retry}/${MAX_RETRIES} — reverting changes"
                git checkout -- . 2>/dev/null || true
            fi

            # --- IMPLEMENT ---
            show_progress "${current}" "${total}" "${task_id}" "IMPLEMENT (${IMPLEMENT_MODEL})"
            local impl_prompt
            impl_prompt="$(expand_prompt "${PROMPTS_DIR}/implement.md" "${task_id}")"

            if ! run_claude "implement" "${task_id}" "${impl_prompt}" "${IMPLEMENT_MODEL}" "${retry}"; then
                log_warn "[${task_id}] Implementation failed"
                continue
            fi

            # --- POST-IMPLEMENT TEST ---
            show_progress "${current}" "${total}" "${task_id}" "POST-IMPLEMENT TEST"
            if ! run_tests "post-implement"; then
                log_warn "[${task_id}] Post-implement tests failed"
                continue
            fi

            # --- REVIEW ---
            show_progress "${current}" "${total}" "${task_id}" "REVIEW (${REVIEW_MODEL})"
            local review_prompt
            review_prompt="$(expand_prompt "${PROMPTS_DIR}/review.md" "${task_id}")"

            if ! run_claude "review" "${task_id}" "${review_prompt}" "${REVIEW_MODEL}" "${retry}"; then
                log_warn "[${task_id}] Review failed"
                continue
            fi

            # --- POST-REVIEW TEST ---
            show_progress "${current}" "${total}" "${task_id}" "POST-REVIEW TEST"
            if ! run_tests "post-review"; then
                log_warn "[${task_id}] Post-review tests failed"
                continue
            fi

            # --- VERIFY ---
            show_progress "${current}" "${total}" "${task_id}" "VERIFY (${REVIEW_MODEL})"
            local verify_prompt
            verify_prompt="$(expand_prompt "${PROMPTS_DIR}/verify.md" "${task_id}")"

            if ! run_claude "verify" "${task_id}" "${verify_prompt}" "${REVIEW_MODEL}" "${retry}"; then
                log_warn "[${task_id}] Verification failed"
                continue
            fi

            # --- POST-VERIFY TEST ---
            show_progress "${current}" "${total}" "${task_id}" "POST-VERIFY TEST"
            if ! run_tests "post-verify"; then
                log_warn "[${task_id}] Post-verify tests failed"
                continue
            fi

            # --- COMMIT ---
            show_progress "${current}" "${total}" "${task_id}" "COMMIT"
            git add -A
            if git diff --cached --quiet; then
                log_warn "[${task_id}] No changes to commit (review/verify made no modifications)"
            else
                git commit -m "$(cat <<EOF
feat(${SPRINT_TAG}): implement ${task_id} - ${task_name}

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
                )"
                log_ok "[${task_id}] Committed"
            fi

            task_success=true
            break
        done

        if [[ "${task_success}" != "true" ]]; then
            log_error "[${task_id}] FAILED after ${MAX_RETRIES} attempts. Aborting."
            log_error "Check logs: ${LOG_DIR}/${task_id}_*.log"
            exit 1
        fi

        log_ok "[${task_id}] DONE (${current}/${total})"
    done

    echo ""
    echo "============================================"
    echo "  Sprint ${SPRINT_NAME} COMPLETED"
    echo "  ${total} tasks implemented successfully"
    echo "============================================"
    log_ok "Sprint ${SPRINT_NAME} completed. All ${total} tasks done."
}

main "$@"
