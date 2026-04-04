#!/usr/bin/env bash
# sbom-100-projects.sh
#
# Clone 100 common open-source projects and generate BSI-compliant SBOMs for each.
# Prints a pass/fail summary table and writes individual SBOMs to $OUTPUT_DIR.
#
# Usage:
#   ./scripts/sbom-100-projects.sh [OPTIONS]
#
# Options:
#   --binary PATH     Path to transparenz binary (default: ./build/transparenz)
#   --output DIR      Directory to write SBOMs and results (default: ./test-results/sbom-100)
#   --format FORMAT   SBOM format: spdx or cyclonedx (default: cyclonedx)
#   --bsi             Enable BSI TR-03183-2 enrichment (default: off)
#   --jobs N          Parallel clone+generate workers (default: 4)
#   --shallow         Use --depth=1 git clone (default: on)
#   --no-shallow      Disable shallow clone
#   --skip-large      Skip known very large repos (linux-kernel-tools, llvm, pytorch, tensorflow, cockroachdb)
#   --help            Show this help
#
# Exit code: 0 if all projects succeed, 1 if any fail.

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
BINARY="$(cd "$(dirname "$0")/.." && pwd)/build/transparenz"
OUTPUT_DIR="$(cd "$(dirname "$0")/.." && pwd)/test-results/sbom-100"
FORMAT="cyclonedx"
BSI_FLAG=""
JOBS=4
SHALLOW="--depth=1"
SKIP_LARGE=""

# Repos known to be very large (slow or likely to time out)
# Stored as colon-separated string so it can be exported to xargs subshells
LARGE_REPOS_STR="linux-kernel-tools:llvm:pytorch:tensorflow:cockroachdb"

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)   BINARY="$2";     shift 2 ;;
    --output)   OUTPUT_DIR="$2"; shift 2 ;;
    --format)   FORMAT="$2";     shift 2 ;;
    --bsi)      BSI_FLAG="--bsi-compliant"; shift ;;
    --jobs)     JOBS="$2";       shift 2 ;;
    --shallow)  SHALLOW="--depth=1"; shift ;;
    --no-shallow) SHALLOW="";   shift ;;
    --skip-large) SKIP_LARGE="true"; shift ;;
    --help)
      sed -n '/^# Usage/,/^[^#]/p' "$0" | grep '^#' | sed 's/^# \?//'
      exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# ── Validation ────────────────────────────────────────────────────────────────
if [[ ! -x "$BINARY" ]]; then
  echo "ERROR: transparenz binary not found or not executable: $BINARY" >&2
  echo "       Run 'make build' first." >&2
  exit 1
fi

if ! command -v git &>/dev/null; then
  echo "ERROR: git is required" >&2
  exit 1
fi

# ── 100 projects ─────────────────────────────────────────────────────────────
# Format: "slug|git-clone-url"
# Covers: Go, Python, JavaScript/TypeScript, Rust, Java, C/C++, Ruby, PHP, .NET
declare -a PROJECTS=(
  # ── Go ─────────────────────────────────────────────────────────────────────
  "kubernetes|https://github.com/kubernetes/kubernetes.git"
  "prometheus|https://github.com/prometheus/prometheus.git"
  "grafana|https://github.com/grafana/grafana.git"
  "traefik|https://github.com/traefik/traefik.git"
  "etcd|https://github.com/etcd-io/etcd.git"
  "docker-cli|https://github.com/docker/cli.git"
  "containerd|https://github.com/containerd/containerd.git"
  "helm|https://github.com/helm/helm.git"
  "terraform|https://github.com/hashicorp/terraform.git"
  "vault|https://github.com/hashicorp/vault.git"
  "consul|https://github.com/hashicorp/consul.git"
  "hugo|https://github.com/gohugoio/hugo.git"
  "caddy|https://github.com/caddyserver/caddy.git"
  "minio|https://github.com/minio/minio.git"
  "cockroachdb|https://github.com/cockroachdb/cockroach.git"
  "influxdb|https://github.com/influxdata/influxdb.git"
  "istio|https://github.com/istio/istio.git"
  "argo-cd|https://github.com/argoproj/argo-cd.git"
  "flux|https://github.com/fluxcd/flux2.git"
  "cilium|https://github.com/cilium/cilium.git"
  # ── Python ─────────────────────────────────────────────────────────────────
  "flask|https://github.com/pallets/flask.git"
  "django|https://github.com/django/django.git"
  "fastapi|https://github.com/fastapi/fastapi.git"
  "requests|https://github.com/psf/requests.git"
  "numpy|https://github.com/numpy/numpy.git"
  "pandas|https://github.com/pandas-dev/pandas.git"
  "scikit-learn|https://github.com/scikit-learn/scikit-learn.git"
  "pytorch|https://github.com/pytorch/pytorch.git"
  "tensorflow|https://github.com/tensorflow/tensorflow.git"
  "celery|https://github.com/celery/celery.git"
  "airflow|https://github.com/apache/airflow.git"
  "ansible|https://github.com/ansible/ansible.git"
  "httpx|https://github.com/encode/httpx.git"
  "pydantic|https://github.com/pydantic/pydantic.git"
  "sqlalchemy|https://github.com/sqlalchemy/sqlalchemy.git"
  # ── JavaScript / TypeScript ────────────────────────────────────────────────
  "react|https://github.com/facebook/react.git"
  "vue|https://github.com/vuejs/core.git"
  "angular|https://github.com/angular/angular.git"
  "next-js|https://github.com/vercel/next.js.git"
  "svelte|https://github.com/sveltejs/svelte.git"
  "express|https://github.com/expressjs/express.git"
  "nestjs|https://github.com/nestjs/nest.git"
  "vite|https://github.com/vitejs/vite.git"
  "webpack|https://github.com/webpack/webpack.git"
  "prettier|https://github.com/prettier/prettier.git"
  "eslint|https://github.com/eslint/eslint.git"
  "typescript|https://github.com/microsoft/TypeScript.git"
  "deno|https://github.com/denoland/deno.git"
  "bun|https://github.com/oven-sh/bun.git"
  "axios|https://github.com/axios/axios.git"
  # ── Rust ───────────────────────────────────────────────────────────────────
  "ripgrep|https://github.com/BurntSushi/ripgrep.git"
  "tokio|https://github.com/tokio-rs/tokio.git"
  "serde|https://github.com/serde-rs/serde.git"
  "actix-web|https://github.com/actix/actix-web.git"
  "axum|https://github.com/tokio-rs/axum.git"
  "rust-analyzer|https://github.com/rust-lang/rust-analyzer.git"
  "alacritty|https://github.com/alacritty/alacritty.git"
  "bat|https://github.com/sharkdp/bat.git"
  "fd|https://github.com/sharkdp/fd.git"
  "zoxide|https://github.com/ajeetdsouza/zoxide.git"
  # ── Java / JVM ─────────────────────────────────────────────────────────────
  "spring-boot|https://github.com/spring-projects/spring-boot.git"
  "elasticsearch|https://github.com/elastic/elasticsearch.git"
  "kafka|https://github.com/apache/kafka.git"
  "gradle|https://github.com/gradle/gradle.git"
  "quarkus|https://github.com/quarkusio/quarkus.git"
  "micronaut|https://github.com/micronaut-projects/micronaut-core.git"
  "netty|https://github.com/netty/netty.git"
  "flink|https://github.com/apache/flink.git"
  "cassandra|https://github.com/apache/cassandra.git"
  "zookeeper|https://github.com/apache/zookeeper.git"
  # ── C / C++ ────────────────────────────────────────────────────────────────
  "redis|https://github.com/redis/redis.git"
  "nginx|https://github.com/nginx/nginx.git"
  "curl|https://github.com/curl/curl.git"
  "git|https://github.com/git/git.git"
  "sqlite|https://github.com/sqlite/sqlite.git"
  "postgresql|https://github.com/postgres/postgres.git"
  "linux-kernel-tools|https://github.com/torvalds/linux.git"
  "ffmpeg|https://github.com/FFmpeg/FFmpeg.git"
  "llvm|https://github.com/llvm/llvm-project.git"
  "openssl|https://github.com/openssl/openssl.git"
  # ── Ruby ───────────────────────────────────────────────────────────────────
  "rails|https://github.com/rails/rails.git"
  "jekyll|https://github.com/jekyll/jekyll.git"
  "devise|https://github.com/heartcombo/devise.git"
  "sidekiq|https://github.com/sidekiq/sidekiq.git"
  "rspec|https://github.com/rspec/rspec-core.git"
  # ── PHP ────────────────────────────────────────────────────────────────────
  "laravel|https://github.com/laravel/laravel.git"
  "symfony|https://github.com/symfony/symfony.git"
  "composer|https://github.com/composer/composer.git"
  "wordpress|https://github.com/WordPress/WordPress.git"
  "phpmyadmin|https://github.com/phpmyadmin/phpmyadmin.git"
  # ── .NET / C# ──────────────────────────────────────────────────────────────
  "aspnetcore|https://github.com/dotnet/aspnetcore.git"
  "runtime|https://github.com/dotnet/runtime.git"
  "ef-core|https://github.com/dotnet/efcore.git"
  "masstransit|https://github.com/MassTransit/MassTransit.git"
  "serilog|https://github.com/serilog/serilog.git"
  # ── Infrastructure / DevOps ────────────────────────────────────────────────
  "ansible-lint|https://github.com/ansible/ansible-lint.git"
  "packer|https://github.com/hashicorp/packer.git"
  "nomad|https://github.com/hashicorp/nomad.git"
  "trivy|https://github.com/aquasecurity/trivy.git"
  "syft|https://github.com/anchore/syft.git"
)

# ── Setup ─────────────────────────────────────────────────────────────────────
CLONE_DIR="$OUTPUT_DIR/repos"
SBOM_DIR="$OUTPUT_DIR/sboms"
LOG_DIR="$OUTPUT_DIR/logs"
RESULTS_FILE="$OUTPUT_DIR/results.tsv"

mkdir -p "$CLONE_DIR" "$SBOM_DIR" "$LOG_DIR"

echo -e "slug\tstatus\texit_code\tduration_s\tsbom_file\terror" > "$RESULTS_FILE"

# Colour helpers (no-op if not a terminal)
if [[ -t 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''
fi

PASS=0
FAIL=0
SKIP=0
TOTAL=${#PROJECTS[@]}

echo -e "${BOLD}transparenz SBOM generation — ${TOTAL} projects${RESET}"
echo -e "Binary : $BINARY"
echo -e "Output : $OUTPUT_DIR"
echo -e "Format : $FORMAT"
echo -e "BSI    : ${BSI_FLAG:-(disabled)}"
echo -e "Jobs   : $JOBS"
echo -e "Shallow: ${SHALLOW:-(full clone)}"
echo ""

# ── Worker function ───────────────────────────────────────────────────────────
process_project() {
  local entry="$1"
  local slug="${entry%%|*}"
  local url="${entry##*|}"

  local repo_dir="$CLONE_DIR/$slug"
  local sbom_file="$SBOM_DIR/${slug}.json"
  local log_file="$LOG_DIR/${slug}.log"
  local start_time end_time duration exit_code error_msg status

  start_time=$(date +%s)

  # ── Skip large repos if requested ────────────────────────────────────────
  if [[ "${SKIP_LARGE:-}" == "true" ]]; then
    IFS=: read -ra _large_repos <<< "${LARGE_REPOS_STR:-}"
    for large_slug in "${_large_repos[@]}"; do
      if [[ "$slug" == "$large_slug" ]]; then
        printf "%s\tSKIP\t0\t0\t\tskipped (large repo)\n" "$slug" >> "$RESULTS_FILE"
        echo -e "  ${YELLOW}SKIP${RESET} $slug: skipped (large repo)"
        return
      fi
    done
  fi

  # ── Skip if SBOM already generated from a previous run ───────────────────
  if [[ -s "$sbom_file" ]]; then
    end_time=$(date +%s)
    duration=$(( end_time - start_time ))
    echo -e "  ${YELLOW}SKIP${RESET} $slug: SBOM already exists, skipping"
    printf "%s\tSKIP\t0\t%d\t%s\t%s\n" "$slug" "$duration" "$(basename "$sbom_file")" "already exists" >> "$RESULTS_FILE"
    return
  fi

  # ── Clone ────────────────────────────────────────────────────────────────
  if [[ -d "$repo_dir/.git" ]]; then
    echo "[$(date -u +%H:%M:%S)] $slug: repo already cloned, skipping clone" >> "$log_file"
  else
    echo "[$(date -u +%H:%M:%S)] $slug: cloning $url ..." >> "$log_file"
    CLONE_OK=false
    for _attempt in 1 2 3; do
      if git clone $SHALLOW --single-branch --quiet "$url" "$repo_dir" >> "$log_file" 2>&1; then
        CLONE_OK=true
        break
      fi
      echo "[$(date -u +%H:%M:%S)] $slug: clone attempt $_attempt failed, retrying in $(( _attempt * 5 ))s ..." >> "$log_file"
      rm -rf "$repo_dir"
      sleep $(( _attempt * 5 ))
    done
    if [[ "$CLONE_OK" != "true" ]]; then
      end_time=$(date +%s)
      duration=$(( end_time - start_time ))
      error_msg="git clone failed (3 attempts)"
      echo -e "  ${RED}FAIL${RESET} $slug: $error_msg (${duration}s)"
      printf "%s\tFAIL\t1\t%d\t\t%s\n" "$slug" "$duration" "$error_msg" >> "$RESULTS_FILE"
      return
    fi
  fi

  # ── Generate SBOM ────────────────────────────────────────────────────────
  echo "[$(date -u +%H:%M:%S)] $slug: generating SBOM ..." >> "$log_file"
  set +e
  "$BINARY" generate "$repo_dir" \
    --format "$FORMAT" \
    --output "$sbom_file" \
    $BSI_FLAG \
    >> "$log_file" 2>&1
  exit_code=$?
  set -e

  # ── Delete repo immediately to free disk space ────────────────────────────
  echo "[$(date -u +%H:%M:%S)] $slug: removing cloned repo to free disk ..." >> "$log_file"
  rm -rf "$repo_dir"

  end_time=$(date +%s)
  duration=$(( end_time - start_time ))

  if [[ $exit_code -eq 0 && -s "$sbom_file" ]]; then
    status="PASS"
    error_msg=""
    echo -e "  ${GREEN}PASS${RESET} $slug (${duration}s)"
  else
    status="FAIL"
    error_msg="transparenz exit $exit_code"
    if [[ ! -s "$sbom_file" ]]; then
      error_msg="$error_msg (empty output)"
    fi
    echo -e "  ${RED}FAIL${RESET} $slug: $error_msg (${duration}s)"
  fi

  printf "%s\t%s\t%d\t%d\t%s\t%s\n" \
    "$slug" "$status" "$exit_code" "$duration" \
    "$(basename "$sbom_file" 2>/dev/null || echo '')" \
    "$error_msg" >> "$RESULTS_FILE"
}

export -f process_project
export BINARY FORMAT BSI_FLAG CLONE_DIR SBOM_DIR LOG_DIR RESULTS_FILE SHALLOW
export RED GREEN YELLOW CYAN BOLD RESET
export SKIP_LARGE
export LARGE_REPOS_STR

# xargs calls process_project with each entry; output goes directly to terminal
# (no subshell buffering) so progress is visible in real time.
xargs -a "$WORK_FILE" -d '\n' -P "$JOBS" -I {} bash -c 'process_project "$@"' _ {}

rm -f "$WORK_FILE"

# ── Tally results from TSV (skip header line) ─────────────────────────────────
while IFS=$'\t' read -r slug status _rest; do
  case "$status" in
    PASS) (( PASS++ )) ;;
    SKIP) (( SKIP++ )) ;;
    FAIL) (( FAIL++ )) ;;
  esac
done < <(tail -n +2 "$RESULTS_FILE")

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}Results: ${GREEN}${PASS} passed${RESET}  ${RED}${FAIL} failed${RESET}  ${YELLOW}${SKIP} skipped${RESET}  / ${TOTAL} total"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo "Results TSV : $RESULTS_FILE"
echo "SBOMs       : $SBOM_DIR"
echo "Logs        : $LOG_DIR"
echo ""

if [[ $FAIL -gt 0 ]]; then
  echo -e "${RED}Failed projects:${RESET}"
  grep -P '\tFAIL\t' "$RESULTS_FILE" | awk -F'\t' '{printf "  %-40s exit=%s  %s\n", $1, $3, $6}' || true
  echo ""
fi

[[ $FAIL -eq 0 ]]
