// "How it works": every method and algorithm, stage by stage, with where it lives and what it protects.
type Row = { what: string; method: string; why: string; ref?: string };
type Stage = { id: string; title: string; summary: string; rows: Row[] };

const STAGES: Stage[] = [
  {
    id: "params",
    title: "1. Shared parameters",
    summary: "Everyone must agree on the mathematics before anything else, and be able to check nobody chose it with a trapdoor.",
    rows: [
      { what: "Group", method: "Schnorr group: 2048-bit prime p, 256-bit prime q dividing p − 1, generator g of the order-q subgroup", why: "All encryption and proofs happen in this group. 2048/256 is the classical size recommended through 2030.", ref: "NIST SP 800-57" },
      { what: "Parameter generation", method: "p, q and g derived from a public seed with SHAKE-256 and Miller–Rabin primality tests; CI re-derives them", why: "Nothing-up-my-sleeve: anyone can recompute them, so no one can have planted a weak group.", ref: "spec/protocol.md §2" },
      { what: "Fiat–Shamir hashing", method: "SHA-256 over a type-length-value encoding, domain-separated (\"chunaviq/v1/<purpose>\")", why: "Turns interactive proofs into non-interactive ones; the unambiguous encoding stops two different inputs hashing alike.", ref: "Fiat & Shamir 1986" },
      { what: "Record encoding", method: "Canonical JSON: sorted keys, no whitespace, ASCII, integers as lowercase hex", why: "Every implementation produces byte-identical entries, so hashes and signatures agree across Python and TypeScript.", ref: "spec/record-format.md" },
      { what: "Role signatures", method: "Ed25519 for the officer, the record operator, the eligibility authority, each trustee, operator cards and observers", why: "Every published entry says who vouches for it and cannot be altered without breaking the signature.", ref: "RFC 8032" },
    ],
  },
  {
    id: "keys",
    title: "2. The election key and its custody",
    summary: "One key for the whole country, split so no fewer than three of five trustees can use it, and each piece locked in hardware.",
    rows: [
      { what: "Distributed key generation", method: "Feldman verifiable secret sharing, 3-of-5: each trustee commits to a random polynomial with a Schnorr proof for every coefficient; shares are checked against the commitments", why: "No one ever holds the whole decryption key; a cheating trustee is caught when its shares fail the check.", ref: "Feldman 1987; Pedersen 1991" },
      { what: "One national key", method: "All 543 constituencies encrypt under the same joint key; each trustee holds exactly one share", why: "Separate keys per seat would add nothing (the same five people would hold all of them) and multiply the shares to protect by 543.", ref: "docs/key-ceremony.md" },
      { what: "Hardware custody", method: "A trustee applet that runs inside the HSM (Thales Luna Functionality Module, Entrust nShield CodeSafe or Utimaco CryptoServer SDK); shares travel HSM to HSM encrypted with X25519 + HKDF-SHA256 + AES-256-GCM", why: "Standard PKCS#11 cannot compute a decryption share without exporting the key; custom code inside the boundary can.", ref: "src/chunaviq/custody.py" },
      { what: "Use policy inside the HSM", method: "Decrypts only: after a CLOSED entry signed by the officer, with 2 of 3 operator-card approvals, with 2 of 3 independent observers attesting what is being decrypted, within a budget, never the same request twice", why: "No insider, alone or with one other, can decrypt anything; nothing can be decrypted while voting is open; an individual ballot cannot be passed off as a total.", ref: "custody.TrusteeApplet.decrypt" },
      { what: "HSM audit log", method: "Hash-chained, signed by a key generated inside the HSM; published after the election and checked by the verifier", why: "Every use of every share is visible after the fact.", ref: "custody.hsm_logs check" },
    ],
  },
  {
    id: "identity",
    title: "3. Proving who you are",
    summary: "Aadhaar or PAN, resolving to one entry on the electoral roll. In this prototype every identity service is synthetic.",
    rows: [
      { what: "Aadhaar + OTP / face", method: "UIDAI authentication through a licensed AUA/KUA; returns a UID token, never the Aadhaar number", why: "Strong remote identity proof with a phone or a face the voter physically has.", ref: "Aadhaar Act 2016; Good Governance Rules 2020, amended 2025" },
      { what: "PAN", method: "Income Tax PAN verification (number, name, date of birth), plus an OTP to the mobile on the electoral roll, plus a face match to the roll photograph", why: "PAN verification alone checks facts printed on the card. The two extra factors prove the holder is present.", ref: "Protean Online PAN Verification" },
      { what: "Roll linkage", method: "Identifiers stored only as keyed hashes (HMAC-SHA256); both documents resolve to the same roll entry", why: "Someone with Aadhaar and PAN still gets one registration; raw identity numbers are never stored.", ref: "s.23(5) RP Act 1950 (Form 6B)" },
      { what: "Brute-force protection", method: "Lockout after 5 failed attempts per identifier; OTPs single-use with 3 tries", why: "Guessing codes or faces does not scale.", ref: "eligibility.py" },
    ],
  },
  {
    id: "register",
    title: "4. Registering a voting tag",
    summary: "Your phone creates a tag the authority records against your roll entry. The tag's secret never leaves the phone.",
    rows: [
      { what: "Tag", method: "T = g^t with t random on the device", why: "Ballots carry an encryption of T. Only a device that knows t can make one.", ref: "spec/protocol.md §5" },
      { what: "Registration proof", method: "Schnorr proof of knowledge of t, bound to this authentication session", why: "Nobody can register a tag they cannot vote with, or replay someone else's registration.", ref: "Schnorr 1991" },
      { what: "Re-registration", method: "Verifying identity again registers a new tag and silently revokes the old one", why: "A voter whose phone was taken or watched can make everything cast from it stop counting.", ref: "docs/coercion.md" },
      { what: "Polling-day override", method: "Voting in person at a polling station revokes the voter's online tag", why: "The last word always belongs to the voter at a supervised booth.", ref: "docs/coercion.md" },
      { what: "Participation commitment", method: "SHA-256(election ‖ roll entry ‖ random salt), published sorted after close", why: "Each voter can confirm they are counted as registered; nobody else learns who registered.", ref: "eligibility.py" },
    ],
  },
  {
    id: "ballot",
    title: "5. Casting a ballot",
    summary: "Encrypted on the device, with proofs that it is well-formed, under an encrypted tag.",
    rows: [
      { what: "Encryption", method: "Exponential ElGamal: Enc(m; r) = (g^r, g^m·K^r), one ciphertext per option", why: "Ciphertexts multiply to add votes, so totals can be decrypted without decrypting any ballot.", ref: "ElGamal 1985; Cramer, Gennaro, Schoenmakers 1997" },
      { what: "Each box is 0 or 1", method: "Cramer–Damgård–Schoenmakers disjunctive (OR) Chaum–Pedersen proof", why: "A box cannot hold 2 or −1.", ref: "CDS 1994" },
      { what: "Exactly one selection", method: "Chaum–Pedersen proof that the product of all boxes encrypts 1", why: "No overvotes, no blank ballots (abstain or use NOTA).", ref: "Chaum & Pedersen 1992" },
      { what: "Tag proof", method: "Sigma proof of knowledge of (r, t) with tag = (g^r, g^t·K^r), bound to the ballot's contents", why: "The ballot box and the eligibility authority know T but not t, so neither can cast for you.", ref: "sigma.tag_statement" },
      { what: "Tag link (private)", method: "Proof to the ballot box only that the tag ciphertext encrypts T", why: "The box can tell which ballots are revotes of one another; the public cannot.", ref: "sigma.link_statement" },
      { what: "Copy defence", method: "Selection proofs bound to the tag ciphertext; tag proof bound to the selections; no ciphertext may appear twice", why: "Nobody can copy your encrypted vote into their ballot to vote the same way.", ref: "Cortier & Smyth 2011" },
      { what: "Cast-as-intended", method: "Benaloh cast-or-challenge: the device reveals the randomness of a ballot you then discard", why: "A device that encrypts a different choice is caught with the probability you challenge it.", ref: "Benaloh 2006" },
      { what: "No markers", method: "Exact schemas at every level", why: "A voter cannot embed a mark to prove their vote to a buyer.", ref: "finding F-001" },
    ],
  },
  {
    id: "box",
    title: "6. The ballot box",
    summary: "Accepts revotes, refuses everything else, survives retries and floods.",
    rows: [
      { what: "Revoting", method: "Any number of ballots per tag (capped at 30); all are kept, numbered privately", why: "Coerced, bought or mistaken votes can be replaced in private.", ref: "Estonian i-voting model" },
      { what: "Revocation hidden", method: "A revoked tag's ballots are still accepted while voting is open", why: "A coercer holding an old phone sees nothing different after the voter re-registers.", ref: "ballotbox.py" },
      { what: "Idempotent retries", method: "The same ballot under the same tag returns the original receipt", why: "A phone on a bad connection can resend safely; nothing is counted twice.", ref: "ballotbox._prior" },
      { what: "Group commit", method: "Batches of up to 256 ballots in one SQLite transaction and one fsync; receipts only after", why: "Durability without one disk flush per ballot: about 1,200 ballots/s per shard.", ref: "board.append_ballots" },
      { what: "Denial of service", method: "Connection caps, header/body deadlines, size caps, per-client token buckets, load shedding with Retry-After, cheap checks before expensive ones, registered-tag requirement, per-tag rate limit, bounded prover pool", why: "Nobody without a registration can make the server do expensive work; a registration buys at most one expensive check per interval.", ref: "service/sequencer.py" },
      { what: "Sharding", method: "One ballot box and record per constituency (543), with no coordination between them", why: "Tags are registered per constituency, so national capacity grows by adding shards.", ref: "docs/scale.md" },
    ],
  },
  {
    id: "record",
    title: "7. The public record",
    summary: "Append-only, signed, and checkable by anyone.",
    rows: [
      { what: "Log", method: "RFC 6962 / 9162 Merkle tree over canonical entries", why: "Changing, removing or reordering any entry changes every later root.", ref: "RFC 9162" },
      { what: "Checkpoints", method: "Signed roots with consistency proofs from the previous checkpoint", why: "The operator cannot fork history: two different records under one signature are self-evident.", ref: "Certificate Transparency" },
      { what: "Receipts", method: "Tracking code = SHA-256 of the ballot; inclusion proof against a signed checkpoint", why: "Each voter can prove their ballot is in the record, without revealing their vote.", ref: "verify_receipt" },
      { what: "Hour-granular time", method: "Entries carry only the hour", why: "Limits linking a registration to a ballot by timing.", ref: "clock.hour_bucket" },
    ],
  },
  {
    id: "close",
    title: "8. After polls close: which ballot counts",
    summary: "The ballot box decides, in secret, which ballot of each voter counts, and proves it decided honestly.",
    rows: [
      { what: "Finalization", method: "For every ballot: an encrypted flag f (1 = last ballot of a valid tag) and a masked copy of the vote, with an OR-proof of [f = 1 and masked = re-encryption of the vote] or [f = 0 and masked = encryption of zero]", why: "The tally multiplies masked votes, so exactly the final ballots count, and nobody can see which ballots those are.", ref: "sigma.finalize_branches" },
      { what: "Voter's private check", method: "Designated-verifier proof: [flag encrypts 1] OR [I know t]", why: "Convinces the voter their last ballot counts. Because the voter could forge it with t, it is worthless as evidence to a coercer.", ref: "Jakobsson, Sako, Impagliazzo 1996" },
    ],
  },
  {
    id: "mix",
    title: "9. Mixing and counting",
    summary: "Proves every counted ballot belongs to a different, valid voter, without linking any ballot to anyone.",
    rows: [
      { what: "Verifiable shuffle", method: "At least three trustees in turn re-encrypt and permute (tag, flag) pairs, each with a Terelius–Wikström proof; batches of 2,048", why: "If any one mixer keeps its permutation secret, no output can be linked to a ballot.", ref: "Terelius & Wikström 2010; Haenni et al. 2017" },
      { what: "Independent generators", method: "Hash-to-subgroup with SHAKE-256 and cofactor exponentiation", why: "Nobody knows their discrete logs, which the shuffle proof's soundness needs.", ref: "shuffle.generators" },
      { what: "Flags and tags revealed", method: "Threshold decryption of every shuffled flag, then of the tag of every row with flag 1, each share with a Chaum–Pedersen proof", why: "Anyone can check the counted tags are distinct and exactly the registered, not-overridden ones.", ref: "mixing.counted_tags check" },
      { what: "Threshold decryption of totals", method: "Each of 3 trustees publishes α^{s_i} with a proof; Lagrange interpolation at 0 combines them", why: "Only per-option totals are ever decrypted.", ref: "Shamir 1979" },
      { what: "Recovering counts", method: "Baby-step giant-step discrete log, O(√n)", why: "Counts up to 58 lakh per option in about 70 ms.", ref: "Shanks 1971" },
      { what: "Decision", method: "First past the post; NOTA counted, cannot win; ties left to the returning officer's lot (s.65 RP Act 1951)", why: "Software must not perform a witnessed human act.", ref: "administration.decide" },
    ],
  },
  {
    id: "verify",
    title: "10. Verification and assurance",
    summary: "Nothing above needs to be trusted: it is all re-checked from the public record.",
    rows: [
      { what: "Two independent verifiers", method: "Python (chunaviq_verify, no imports from the election code) and TypeScript (this website); CI checks records made by each with the other", why: "A bug shared by the election code and its checker would be invisible; two implementations make that unlikely.", ref: "tests/test_end_to_end.py" },
      { what: "Bounded memory", method: "Streaming verification with an on-disk index; parallel proof checking", why: "A constituency with 58 lakh ballots verifies on an ordinary machine.", ref: "test_verifier_memory_does_not_grow" },
      { what: "Federation", method: "Signed national manifest, shard index and result; every shard verified and bound to the one national key", why: "A missing, extra or swapped constituency fails the national election.", ref: "spec/federation.md" },
      { what: "Testing", method: "Property-based tests and fuzzing (Hypothesis), tamper tests against insiders holding keys, concurrency races, 10,000-voter evidence run, HTTP dress rehearsal under seven kinds of attack", why: "Every claim on this page has a test that would fail if it were false.", ref: "docs/test-strategy.md" },
    ],
  },
];

export function Methods() {
  return (
    <main className="page">
      <h1>How it works</h1>
      <p className="lede">
        Every method and algorithm ChunavIQ uses, in the order an election uses them. Each row says what it protects. File and test names point to the
        code; references point to the original work.
      </p>
      <nav className="toc" aria-label="Stages">
        {STAGES.map((s) => (
          <a key={s.id} href={`#/methods/${s.id}`} onClick={(ev) => (ev.preventDefault(), document.getElementById(s.id)?.scrollIntoView())}>
            {s.title}
          </a>
        ))}
      </nav>
      {STAGES.map((s) => (
        <section key={s.id} id={s.id} className="method-stage" aria-labelledby={`${s.id}-h`}>
          <h2 id={`${s.id}-h`}>{s.title}</h2>
          <p>{s.summary}</p>
          <div className="table-wrap">
            <table className="methods-table">
              <thead>
                <tr>
                  <th scope="col">Part</th>
                  <th scope="col">Method</th>
                  <th scope="col">Why</th>
                  <th scope="col">Reference</th>
                </tr>
              </thead>
              <tbody>
                {s.rows.map((r) => (
                  <tr key={r.what}>
                    <th scope="row">{r.what}</th>
                    <td>{r.method}</td>
                    <td>{r.why}</td>
                    <td className="ref">{r.ref}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ))}
      <section className="method-stage">
        <h2>What it does not solve</h2>
        <ul>
          <li>A coercer who copies the phone's secret can see that the voter later re-registered or voted in person (though not that they simply revoted).</li>
          <li>The ballot box and the eligibility authority together could learn who voted when (never how). This is the price of revoting.</li>
          <li>Network-level floods need a CDN or anycast scrubbing layer in front; the server handles application-level abuse.</li>
          <li>A malware-infected phone that also hides from Benaloh challenges can change a vote; device diversity and challenges reduce, not remove, this.</li>
        </ul>
      </section>
    </main>
  );
}
