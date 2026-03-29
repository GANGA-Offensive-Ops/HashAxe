#!/bin/bash

# =============================================================================
# Hashaxe V1 - Shared Library
# =============================================================================
# Sourced by all test suite scripts. Do NOT execute directly.
#
# Author: GANGA Offensive Ops
# Version: 1.0.0 (fixed, production-grade)
# Date: March 2026
#
# =============================================================================

# Guard: prevent double-sourcing
[[ -n "${_Hashaxe_LIB_LOADED:-}" ]] && return 0
readonly _Hashaxe_LIB_LOADED=1

set -uo pipefail

# =============================================================================
# TERMINAL COLORS
# =============================================================================
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'
readonly DIM='\033[2m'

# =============================================================================
# GLOBAL STATE (initialized here; test files may override DEFAULT_TIMEOUT)
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_DIR="${SCRIPT_DIR}/logs"
START_TIME=$(date +%s)

# Counters — all start at 0
CURRENT_COMMAND=0
SKIPPED_COMMANDS=0
FAILED_COMMANDS=0
PASSED_COMMANDS=0
TIMEOUT_COMMANDS=0

# Signal handling state
CURRENT_PID=""

# Runtime flags (may be overridden by parse_args)
RESUME_AT=0
DRY_RUN=0
RUNTIME_TIMEOUT_OVERRIDE=0

# Log file — set in init_logging() after SUITE_NAME is known
LOG_FILE=""

# =============================================================================
# ARGUMENT PARSING
# =============================================================================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --resume)
                if [[ -z "${2:-}" ]] || ! [[ "${2}" =~ ^[0-9]+$ ]]; then
                    echo -e "${RED}[ERROR]${NC} --resume requires a positive integer argument" >&2
                    exit 1
                fi
                RESUME_AT="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=1
                shift
                ;;
            --timeout)
                if [[ -z "${2:-}" ]] || ! [[ "${2}" =~ ^[0-9]+$ ]]; then
                    echo -e "${RED}[ERROR]${NC} --timeout requires a positive integer argument" >&2
                    exit 1
                fi
                RUNTIME_TIMEOUT_OVERRIDE="$2"
                shift 2
                ;;
            --help|-h)
                echo -e "Usage: $0 [OPTIONS]"
                echo -e "  --resume N    Skip first N commands, start from N+1"
                echo -e "  --dry-run     Print commands without executing"
                echo -e "  --timeout N   Override all per-command timeouts with N seconds"
                echo -e "  --help        Show this message"
                exit 0
                ;;
            *)
                echo -e "${YELLOW}[WARN]${NC} Unknown argument: $1" >&2
                shift
                ;;
        esac
    done
}

# =============================================================================
# LOGGING SETUP
# =============================================================================
init_logging() {
    local suite_name="${SUITE_NAME:-UNKNOWN}"
    local safe_name
    safe_name="$(echo "$suite_name" | tr ' &/' '___')"
    LOG_FILE="${LOG_DIR}/shadowhashaxe_${safe_name}_$(date +%Y%m%d_%H%M%S).log"

    mkdir -p "$LOG_DIR" || {
        echo -e "${YELLOW}[WARN]${NC} Could not create log dir: $LOG_DIR — logging disabled" >&2
        LOG_FILE="/dev/null"
        return 0
    }

    # Tee stdout/stderr: terminal keeps ANSI colors, log file gets clean stripped text
    exec > >(tee >(sed 's/\x1b\[[0-9;]*[mGKHF]//g' >> "$LOG_FILE")) 2>&1
    echo "# Hashaxe Log — Suite: ${suite_name} — Started: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
}

# =============================================================================
# SIGNAL HANDLER
# =============================================================================
sigint_handler() {
    local pid="$CURRENT_PID"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        echo -e "\n${YELLOW}[SKIP]${NC} Ctrl+C — killing PID ${pid} and children..."
        # Kill entire process group if setsid was used; fallback to single PID + children
        kill -TERM -- "-${pid}" 2>/dev/null \
            || { kill -TERM "$pid" 2>/dev/null; pkill -TERM -P "$pid" 2>/dev/null; }
        # NOTE: SKIPPED_COMMANDS is incremented in execute_command on exit 130/143.
        # Do NOT increment here — that was the v1.0 double-count bug.
    fi
}

trap sigint_handler SIGINT

# =============================================================================
# OUTPUT FORMATTING
# =============================================================================
print_header() {
    local suite="${SUITE_NAME:-TEST SUITE}"
    local total="${TOTAL_COMMANDS:-0}"
    local timeout_info=""
    [[ "${DEFAULT_TIMEOUT:-0}" -gt 0 ]] && timeout_info="\n${CYAN}Default Timeout:${NC} ${DEFAULT_TIMEOUT}s per command"

    echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════════════════════════════════════════${NC}"
    printf "${BOLD}${BLUE}%-78s${NC}\n" "  Hashaxe V1 — ${suite}"
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Started:${NC}           $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${CYAN}Total Commands:${NC}    ${total}"
    echo -e "${CYAN}Project Dir:${NC}       ${PROJECT_DIR}"
    echo -e "${CYAN}Log File:${NC}          ${LOG_FILE}"
    [[ "${DEFAULT_TIMEOUT:-0}" -gt 0 ]] && echo -e "${CYAN}Default Timeout:${NC}   ${DEFAULT_TIMEOUT}s per command"
    [[ "$RESUME_AT" -gt 0 ]]            && echo -e "${YELLOW}Resume From:${NC}       Command $((RESUME_AT + 1))"
    [[ "$DRY_RUN" -eq 1 ]]              && echo -e "${MAGENTA}Mode:${NC}              DRY RUN (no execution)"
    [[ "$RUNTIME_TIMEOUT_OVERRIDE" -gt 0 ]] && \
        echo -e "${YELLOW}Timeout Override:${NC}  ${RUNTIME_TIMEOUT_OVERRIDE}s (all commands)"
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════════════════════════════${NC}\n"
}

print_footer() {
    local end_time
    end_time=$(date +%s)
    local duration=$(( end_time - START_TIME ))
    local minutes=$(( duration / 60 ))
    local seconds=$(( duration % 60 ))
    local total="${TOTAL_COMMANDS:-0}"
    local executed=$(( PASSED_COMMANDS + FAILED_COMMANDS + SKIPPED_COMMANDS + TIMEOUT_COMMANDS ))

    echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  TEST SUITE COMPLETED${NC}"
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Completed:${NC}         $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${CYAN}Duration:${NC}          ${minutes}m ${seconds}s"
    echo -e "${CYAN}Total / Executed:${NC}  ${total} / ${executed}"
    echo -e "${GREEN}  ✓ Passed:${NC}       ${PASSED_COMMANDS}"
    echo -e "${RED}  ✗ Failed:${NC}       ${FAILED_COMMANDS}"
    echo -e "${YELLOW}  ⏱ Timed Out:${NC}   ${TIMEOUT_COMMANDS}"
    echo -e "${YELLOW}  ⏭ Skipped:${NC}     ${SKIPPED_COMMANDS}"
    echo -e "${CYAN}Log File:${NC}          ${LOG_FILE}"
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════════════════════════════${NC}\n"

    # Machine-readable summary to log file
    {
        echo "---"
        echo "RESULT_SUMMARY:"
        echo "  passed:   ${PASSED_COMMANDS}"
        echo "  failed:   ${FAILED_COMMANDS}"
        echo "  timeout:  ${TIMEOUT_COMMANDS}"
        echo "  skipped:  ${SKIPPED_COMMANDS}"
        echo "  duration: ${minutes}m${seconds}s"
    } >> "$LOG_FILE"
}

print_progress() {
    local cmd_num=$1
    local total=$2
    local cmd_desc=$3
    local percentage=0
    [[ $total -gt 0 ]] && percentage=$(( cmd_num * 100 / total ))

    local bar_width=42
    local filled=$(( percentage * bar_width / 100 ))
    local empty=$(( bar_width - filled ))

    local bar=""
    local i
    for (( i=0; i<filled; i++ )); do bar+="█"; done
    for (( i=0; i<empty;  i++ )); do bar+="░"; done

    echo -e "\n${BOLD}${CYAN}┌──────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BOLD}${CYAN}│${NC} [${GREEN}${bar}${NC}] ${BOLD}${percentage}%%${NC} (${cmd_num}/${total})"
    echo -e "${BOLD}${CYAN}│${NC} ${BOLD}#${cmd_num}:${NC} ${YELLOW}${cmd_desc}${NC}"
    echo -e "${BOLD}${CYAN}└──────────────────────────────────────────────────────────────────────────┘${NC}"
}

print_result() {
    local status="$1"
    local exit_code="$2"
    local duration="$3"
    local timeout_val="${4:-0}"

    case "$status" in
        PASS)    echo -e "${GREEN}✓ PASSED${NC}   (exit:${exit_code}  duration:${duration}s)" ;;
        FAIL)    echo -e "${RED}✗ FAILED${NC}   (exit:${exit_code}  duration:${duration}s)" ;;
        SKIP)    echo -e "${YELLOW}⏭ SKIPPED${NC}  (Ctrl+C  exit:${exit_code})" ;;
        TIMEOUT) echo -e "${YELLOW}⏱ TIMEOUT${NC}  (exceeded ${timeout_val}s  exit:${exit_code}  duration:${duration}s)" ;;
    esac
}

print_section_divider() {
    local cmd_num=$1
    local total=$2
    if [[ $cmd_num -lt $total ]]; then
        echo -e "${DIM}${BLUE}  ── cmd ${cmd_num} done ── next in 0.5s ──${NC}"
        sleep 0.5
    fi
}

# =============================================================================
# COMMAND EXECUTION ENGINE
# =============================================================================
# Args:
#   $1  cmd          — full shell command string
#   $2  cmd_num      — 1-based sequence number
#   $3  cmd_desc     — human label
#   $4  timeout_val  — seconds (0 = no timeout)
# =============================================================================
execute_command() {
    local cmd="$1"
    local cmd_num=$2
    local cmd_desc="$3"
    local timeout_val="${4:-0}"

    # Runtime timeout override wins over per-command value
    [[ "$RUNTIME_TIMEOUT_OVERRIDE" -gt 0 ]] && timeout_val="$RUNTIME_TIMEOUT_OVERRIDE"

    CURRENT_COMMAND=$cmd_num
    print_progress "$cmd_num" "$TOTAL_COMMANDS" "$cmd_desc"

    echo -e "${CYAN}Cmd:${NC}  $cmd"
    echo -e "${CYAN}Dir:${NC}  $PROJECT_DIR"
    [[ $timeout_val -gt 0 ]] && echo -e "${CYAN}Timeout:${NC} ${timeout_val}s"
    echo -e "${CYAN}──────────────────────────────────────────────────────────────────────────────${NC}"

    local cmd_start
    cmd_start=$(date +%s)

    # -------------------------------------------------------------------------
    # EXECUTION STRATEGY:
    #   - With timeout_val > 0: wrap in coreutils `timeout --kill-after=3`
    #     Exit 124 = SIGTERM timeout  |  Exit 137 = SIGKILL fallback timeout
    #   - Without timeout: run in background, wait for it.
    #     SIGINT handler kills CURRENT_PID + children on Ctrl+C.
    #
    # Both paths run in a subshell that cd's to PROJECT_DIR first, so we don't
    # pollute the main shell's working directory.
    #
    # bash -c used instead of eval: subshell isolation, no current-shell state leakage.
    # -------------------------------------------------------------------------
    local exit_code

    if [[ $timeout_val -gt 0 ]]; then
        # timeout coreutils: exit 124 = clean timeout, exit 137 = SIGKILL fallback
        (
            cd "$PROJECT_DIR" || exit 126
            timeout --kill-after=3 "$timeout_val" bash -c "$cmd"
        ) 2>&1 &
        CURRENT_PID=$!
        wait "$CURRENT_PID" 2>/dev/null
        exit_code=$?
        CURRENT_PID=""
    else
        (
            cd "$PROJECT_DIR" || exit 126
            bash -c "$cmd"
        ) 2>&1 &
        CURRENT_PID=$!
        wait "$CURRENT_PID" 2>/dev/null
        exit_code=$?
        CURRENT_PID=""
    fi

    local cmd_end
    cmd_end=$(date +%s)
    local duration=$(( cmd_end - cmd_start ))

    echo -e "${CYAN}──────────────────────────────────────────────────────────────────────────────${NC}"

    # -------------------------------------------------------------------------
    # RESULT CLASSIFICATION
    # Order matters: TIMEOUT (124/137) checked first, then SKIP (130/143),
    # then PASS (0), then FAIL (everything else).
    # -------------------------------------------------------------------------
    if [[ $exit_code -eq 124 ]] || [[ $exit_code -eq 137 ]]; then
        # coreutils timeout fired
        print_result "TIMEOUT" "$exit_code" "$duration" "$timeout_val"
        TIMEOUT_COMMANDS=$(( TIMEOUT_COMMANDS + 1 ))
        # NOTE: TIMEOUT is tracked separately; it is NOT added to FAILED_COMMANDS.
        # Change this if you want timeouts to count as failures for CI exit codes.

    elif [[ $exit_code -eq 130 ]] || [[ $exit_code -eq 143 ]]; then
        # 130 = SIGINT (Ctrl+C propagated)  |  143 = SIGTERM (our sigint_handler kill)
        # FIX: increment ONLY here. v1.0 also incremented in sigint_handler → double-count.
        print_result "SKIP" "$exit_code" "$duration" "$timeout_val"
        SKIPPED_COMMANDS=$(( SKIPPED_COMMANDS + 1 ))

    elif [[ $exit_code -eq 0 ]]; then
        print_result "PASS" "$exit_code" "$duration" "$timeout_val"
        PASSED_COMMANDS=$(( PASSED_COMMANDS + 1 ))

    else
        print_result "FAIL" "$exit_code" "$duration" "$timeout_val"
        FAILED_COMMANDS=$(( FAILED_COMMANDS + 1 ))
    fi

    echo ""
    print_section_divider "$cmd_num" "$TOTAL_COMMANDS"
    return $exit_code
}

# =============================================================================
# SUITE RUNNER — called from main() in each test file
# Expects:
#   $SUITE_NAME    — set by calling script
#   $COMMANDS[@]   — array set by calling script
#   $DEFAULT_TIMEOUT — set by calling script (0 if no timeout)
# =============================================================================
run_suite() {
    parse_args "$@"

    # Dynamic total — FIX: was hardcoded in v1.0
    TOTAL_COMMANDS=${#COMMANDS[@]}

    init_logging
    print_header

    echo -e "${YELLOW}INSTRUCTIONS:${NC}"
    echo -e "  • ${BOLD}$TOTAL_COMMANDS${NC} commands will run sequentially"
    echo -e "  • ${BOLD}Ctrl+C${NC} skips the current command and moves to next"
    echo -e "  • ${BOLD}Ctrl+C twice rapidly${NC} at the divider pauses exits the script"
    echo -e "  • Use ${BOLD}--resume N${NC} to restart from command N+1\n"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo -e "${MAGENTA}[DRY-RUN MODE]${NC} Listing commands without executing:\n"
    else
        echo -e "${CYAN}Starting in 3 seconds...${NC}"
        sleep 3
    fi

    local cmd_num=1
    local cmd cmd_desc timeout_val rest

    for cmd_entry in "${COMMANDS[@]}"; do
        # --resume: silently skip commands up to RESUME_AT
        if [[ $cmd_num -le $RESUME_AT ]]; then
            echo -e "${DIM}[RESUME] Skipping #${cmd_num} (before resume point ${RESUME_AT})${NC}"
            cmd_num=$(( cmd_num + 1 ))
            continue
        fi

        # Parse "command:::description" or "command:::description:::timeout"
        cmd="${cmd_entry%%:::*}"
        rest="${cmd_entry#*:::}"

        if [[ "$rest" == *:::* ]]; then
            cmd_desc="${rest%%:::*}"
            timeout_val="${rest##*:::}"
        else
            cmd_desc="$rest"
            timeout_val="${DEFAULT_TIMEOUT:-0}"
        fi

        if [[ "$DRY_RUN" -eq 1 ]]; then
            printf "  ${CYAN}#%-3d${NC} %-55s timeout=%ss\n" \
                "$cmd_num" "$cmd_desc" "${timeout_val:-0}"
            cmd_num=$(( cmd_num + 1 ))
            continue
        fi

        execute_command "$cmd" "$cmd_num" "$cmd_desc" "$timeout_val"
        cmd_num=$(( cmd_num + 1 ))
    done

    print_footer

    # Exit code: non-zero if any commands failed (not counting timeouts or skips)
    # Adjust this logic if you want timeouts to also count as failures.
    if [[ $FAILED_COMMANDS -gt 0 ]]; then
        return 1
    else
        return 0
    fi
}
