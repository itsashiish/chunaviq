#!/usr/bin/env bash
# Create the GitHub repository and apply the governance settings from the blueprint.
# Requires: gh (authenticated: `gh auth login`), run from the repository root.
# Usage: scripts/setup-github.sh [repo-name] [public|private]
set -euo pipefail
NAME="${1:-verifiable-election-lab}"
VIS="${2:-public}"
OWNER="$(gh api user --jq .login)"
REPO="$OWNER/$NAME"

sed -i.bak "s/@OWNER/@$OWNER/g" .github/CODEOWNERS && rm -f .github/CODEOWNERS.bak
git add .github/CODEOWNERS
git diff --cached --quiet || git commit -m "Set CODEOWNERS to @$OWNER"

gh repo create "$REPO" "--$VIS" --source . --remote origin --push \
  --description "Research prototype: end-to-end verifiable secret-ballot online election with an independent verifier. Synthetic data only; India legal scope."

gh repo edit "$REPO" --enable-issues --enable-wiki=false --delete-branch-on-merge \
  --enable-squash-merge --enable-merge-commit=false --enable-rebase-merge=false \
  --add-topic e2e-verifiable-voting --add-topic election-security --add-topic research-prototype

# Security features (secret scanning + push protection are free for public repos).
gh api -X PUT "repos/$REPO/vulnerability-alerts" >/dev/null
gh api -X PUT "repos/$REPO/automated-security-fixes" >/dev/null || true
gh api -X PUT "repos/$REPO/private-vulnerability-reporting" >/dev/null || true
gh api -X PATCH "repos/$REPO" --input - >/dev/null <<JSON || echo "note: secret scanning settings need a public repo or GitHub Advanced Security"
{"security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}}
JSON

# Least-privilege default token for Actions; actions must be pinned by full SHA (they are).
gh api -X PUT "repos/$REPO/actions/permissions/workflow" -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false >/dev/null

# Branch protection on main: PRs only, 1 code-owner review (CONTRIBUTING asks for 2 on crypto paths),
# required CI checks, linear history, signed commits, no force pushes or deletions, admins included.
gh api -X PUT "repos/$REPO/branches/main/protection" --input - >/dev/null <<JSON
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["lint", "test (3.11, gmpy2)", "test (3.12, gmpy2)", "test (3.13, gmpy2)",
                 "test (3.11, pure-python)", "test (3.12, pure-python)", "test (3.13, pure-python)", "analyze"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "require_code_owner_reviews": true,
    "dismiss_stale_reviews": true,
    "require_last_push_approval": true
  },
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true
}
JSON
gh api -X POST "repos/$REPO/branches/main/protection/required_signatures" >/dev/null || true

echo "Done: https://github.com/$REPO"
echo "Note: with one maintainer, 'enforce_admins' + required review means you need a second account or collaborator to merge."
