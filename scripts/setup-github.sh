#!/usr/bin/env bash
# Create the GitHub repository and apply the governance settings from the blueprint.
# Requires: gh (authenticated), run from the repository root.
# Usage: scripts/setup-github.sh [repo-name] [private|public]   (default: chunaviq private)
#
# Private repos on a free personal plan cannot use branch protection, secret-scanning
# push protection, CodeQL or dependency review (GitHub Pro / Advanced Security features).
# Those steps are attempted and skipped with a note; re-run with "public" when you open it up.
set -euo pipefail
NAME="${1:-chunaviq}"
VIS="${2:-private}"
OWNER="$(gh api user --jq .login)"
REPO="$OWNER/$NAME"
note() { echo "note: $*"; }

sed -i.bak "s/@OWNER/@$OWNER/g" .github/CODEOWNERS && rm -f .github/CODEOWNERS.bak
git add .github/CODEOWNERS
git diff --cached --quiet || git commit -q -m "Set CODEOWNERS to @$OWNER"

if gh repo view "$REPO" >/dev/null 2>&1; then
  gh repo edit "$REPO" --visibility "$VIS" --accept-visibility-change-consequences
  git remote get-url origin >/dev/null 2>&1 || git remote add origin "https://github.com/$REPO.git"
  git push -u origin main
else
  gh repo create "$REPO" "--$VIS" --source . --remote origin --push \
    --description "ChunavIQ: research prototype of an end-to-end verifiable secret-ballot election with an independent verifier. Synthetic data only."
fi

gh repo edit "$REPO" --enable-issues --enable-wiki=false --delete-branch-on-merge \
  --enable-squash-merge --enable-merge-commit=false --enable-rebase-merge=false \
  --add-topic e2e-verifiable-voting --add-topic election-security --add-topic research-prototype

gh api -X PUT "repos/$REPO/vulnerability-alerts" >/dev/null || note "Dependabot alerts not enabled"

# Least-privilege default token for Actions; actions are pinned by full SHA.
gh api -X PUT "repos/$REPO/actions/permissions/workflow" -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false >/dev/null

if [ "$VIS" = "public" ]; then
  gh api -X PUT "repos/$REPO/private-vulnerability-reporting" >/dev/null || true
  gh api -X PATCH "repos/$REPO" --input - >/dev/null <<JSON || note "secret scanning not enabled"
{"security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}}
JSON
  CHECKS='"lint","test (3.11, gmpy2)","test (3.12, gmpy2)","test (3.13, gmpy2)","test (3.11, pure-python)","test (3.12, pure-python)","test (3.13, pure-python)","analyze"'
else
  CHECKS='"lint","test (3.11, gmpy2)","test (3.12, gmpy2)","test (3.13, gmpy2)","test (3.11, pure-python)","test (3.12, pure-python)","test (3.13, pure-python)"'
fi

# Branch protection on main. Solo maintainer: admins may bypass (STRICT=1 enforces on admins too).
ENFORCE_ADMINS=false; [ "${STRICT:-0}" = "1" ] && ENFORCE_ADMINS=true
gh api -X PUT "repos/$REPO/branches/main/protection" --input - >/dev/null <<JSON || note "branch protection unavailable (private repo on a free plan) - skipped"
{
  "required_status_checks": {"strict": true, "contexts": [$CHECKS]},
  "enforce_admins": $ENFORCE_ADMINS,
  "required_pull_request_reviews": {"required_approving_review_count": 1, "require_code_owner_reviews": true,
                                    "dismiss_stale_reviews": true, "require_last_push_approval": true},
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true
}
JSON
gh api -X POST "repos/$REPO/branches/main/protection/required_signatures" >/dev/null 2>&1 || true

echo "Done: https://github.com/$REPO ($VIS)"
