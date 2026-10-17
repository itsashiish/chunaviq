## What and why

## Security checklist
- [ ] No real personal data, identity numbers, rolls or credentials (synthetic only)
- [ ] Touches `crypto/`, `ballot.py`, `ballotbox.py`, `board.py`, `administration.py` or `chunaviq_verify/`? → needs two reviewers and a spec update
- [ ] If a ballot or record rule changed: `spec/protocol.md`, `spec/record-format.md` and the **independent verifier** updated together
- [ ] New invariant or threat? `spec/invariants.md` / `docs/threat-model.md` updated with a test
- [ ] `pytest -m "not slow"` passes locally
