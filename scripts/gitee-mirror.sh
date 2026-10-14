#!/usr/bin/env bash
#
# gitee-mirror.sh — mirror-sync the ALIRT repository from GitHub to Gitee
#
# Usage:
#   ./scripts/gitee-mirror.sh
#
# Environment variables:
#   GITEE_TOKEN   Gitee personal access token (requires the `projects` scope).
#                 If unset, the script prompts for it interactively (input is
#                 not echoed).
#   GITHUB_URL    Source repository URL, default git@github.com:madsys/ALIRT.git
#                 Can be replaced with https://github.com/madsys/ALIRT.git.
#   GITEE_REPO    Target repository name, default madsys/ALIRT.
#
# Before first use: create an empty repository with the same name on Gitee
# (do NOT initialize it with a README), then either export GITEE_TOKEN or
# paste the token when prompted.
#
# Sync method: git push --mirror (pushes all branches and tags, keeping the
# target identical to the source). Recommended to run once after each release.

set -euo pipefail

GITHUB_URL="${GITHUB_URL:-git@github.com:madsys/ALIRT.git}"
GITEE_REPO="${GITEE_REPO:-madsys/ALIRT}"
GITEE_URL_BASE="https://gitee.com/${GITEE_REPO}.git"

log()  { printf '[gitee-mirror] %s\n' "$*"; }
fail() { printf '[gitee-mirror] ERROR: %s\n' "$*" >&2; exit 1; }

# --- 1. Obtain Gitee credentials ---------------------------------------------

if [[ -z "${GITEE_TOKEN:-}" ]]; then
    if [[ -t 0 ]]; then
        printf 'Please enter your Gitee personal access token (requires the `projects` scope, input is not echoed): '
        read -rs GITEE_TOKEN
        printf '\n'
    else
        fail "Non-interactive environment: provide the token via the GITEE_TOKEN environment variable, e.g.: GITEE_TOKEN=xxx $0"
    fi
fi
[[ -n "${GITEE_TOKEN}" ]] || fail "Gitee token is empty"

# Embed the token in the push URL (note: the token will appear in the local
# process list; unset it after use — see the trap below)
GITEE_PUSH_URL="https://${GITEE_TOKEN}@${GITEE_URL_BASE#https://}"

# --- 2. Prepare a temporary mirror clone --------------------------------------

WORK_DIR="$(mktemp -d /tmp/alirt-gitee-mirror.XXXXXX)"
trap 'rm -rf "${WORK_DIR}"; unset GITEE_TOKEN' EXIT

log "Cloning GitHub source repository (bare mirror): ${GITHUB_URL}"
if ! git clone --mirror "${GITHUB_URL}" "${WORK_DIR}/mirror.git"; then
    fail "Failed to clone ${GITHUB_URL}; please check network access and GitHub permissions (SSH key, or switch to https)"
fi

cd "${WORK_DIR}/mirror.git"

# Force-refresh remote refs to make sure we have the latest branches/tags
log "Fetching latest remote refs"
git remote set-url origin "${GITHUB_URL}"
git fetch origin --prune '+refs/heads/*:refs/heads/*' '+refs/tags/*:refs/tags/*' \
    || fail "Failed to fetch remote updates"

# --- 3. Push to Gitee ---------------------------------------------------------

log "Pushing mirror to Gitee: ${GITEE_URL_BASE}"
if ! git push --mirror "${GITEE_PUSH_URL}"; then
    fail "Push failed. Common causes: 1) the Gitee repository does not exist yet 2) the token lacks the `projects` scope 3) the Gitee repository is not empty (it must be empty for a mirror push). See docs/GITEE.md for details"
fi

log "Sync completed: ${GITEE_URL_BASE}"
