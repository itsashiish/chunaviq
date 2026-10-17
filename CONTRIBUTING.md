# Contributing

## Ground rules

1. **Synthetic data only.** No real names, EPIC numbers, Aadhaar numbers, phone numbers, rolls, constituencies, parties or candidates — anywhere, including issues and screenshots. CI runs `tools/scan_pii.py`.
2. **No custom cryptography beyond the documented constructions.** New primitives need a spec section, a reference, test vectors, and a reviewer who did not write them.
3. **Spec, code and verifier move together.** Changing a ballot, record or tally rule means updating `spec/`, `src/evlab`, **and** `src/evlab_verify` in the same pull request, plus a test that fails without the change.
4. **The verifier never imports `evlab`.** Enforced by `test_verifier_shares_no_code_with_election_package`.
5. **Fail closed.** Missing evidence is a verification failure, never a skip.

## Review

* All changes go through a pull request; direct pushes to `main` are blocked.
* At least one code-owner approval; changes to `src/evlab/crypto`, `src/evlab_verify`, `ballot.py`, `ballotbox.py`, `board.py`, `administration.py` or `.github/` need **two** approvals from people who did not write the change.
* CI (lint, tests on 3 Python versions × 2 arithmetic backends, CodeQL, dependency review) must pass.
* Commits should be signed.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install --require-hashes --no-deps -r requirements/runtime.txt -r requirements/dev.txt
pip install --no-deps --no-build-isolation -e .
pytest -m "not slow"
ruff check src tests tools && ruff format --check src tests tools
```

Updating dependencies: edit `requirements/*.in`, then `pip-compile --generate-hashes --allow-unsafe --strip-extras` in `requirements/`.
