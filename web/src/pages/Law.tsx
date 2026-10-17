// "The law needed": what Indian law would have to say before a system like this could be used in a real election.
type Row = { law: string; now: string; needed: string };

const ROWS: Row[] = [
  {
    law: "Constitution, Articles 324, 326, 327, 328",
    now: "The Election Commission superintends elections to Parliament and State legislatures; elections are on adult suffrage; Parliament (and, within limits, State legislatures) make the laws for conducting them.",
    needed: "No constitutional amendment is obviously required. Parliament would legislate under Article 327; the Election Commission would decide where and when to use it.",
  },
  {
    law: "Representation of the People Act, 1951, s.59",
    now: "Votes are given \"by ballot in such manner as may be prescribed\", and not by proxy except as the Act allows.",
    needed: "Prescribe remote electronic voting as a manner of giving votes, or add a section that does so expressly.",
  },
  {
    law: "RP Act 1951, s.60",
    now: "Special procedure for certain classes: service voters may vote in person, by postal ballot or by proxy; the Commission may notify other classes for postal ballots.",
    needed: "Either let the Commission notify classes of electors who may vote online, or make it an option for all electors with polling stations kept open.",
  },
  {
    law: "RP Act 1951, s.61A",
    now: "Voting machines may be adopted in constituencies the Commission specifies.",
    needed: "An equivalent power for certified remote electronic voting systems, including the rules for keys, trustees, mixing, counting and publication of the record.",
  },
  {
    law: "RP Act 1951, s.62",
    now: "A person may vote only once and in one constituency; votes cast in more than one constituency are void.",
    needed: "Define what counts when revoting is allowed: only the last online ballot under a currently valid registration counts, and a vote in person on polling day cancels the online ballot. Without this, revoting (the main defence against coercion) is not lawful.",
  },
  {
    law: "RP Act 1951, s.128",
    now: "Officials and agents must maintain the secrecy of voting; breach is an offence.",
    needed: "Extend the duty to everyone who runs the system: ballot-box operators, the identity service, trustees, mixers and HSM operators, including a duty not to combine what they know to link voters to ballots.",
  },
  {
    law: "RP Act 1951, Part VI (election petitions) and s.65 (ties by lot)",
    now: "Results are challenged by election petition; ties are decided by lot by the Returning Officer.",
    needed: "Make independent re-verification of the public record the equivalent of a recount, give every candidate and the court a right to run it, and keep ties a human, witnessed act.",
  },
  {
    law: "Conduct of Election Rules, 1961",
    now: "Prescribe EVM/VVPAT polling and postal ballots (including electronically transmitted blank postal ballots for service voters, returned by post).",
    needed: "A new Part for remote voting: registration and re-registration, identity methods, the voting window, revoting, polling-day override, the key ceremony and HSM custody, observers' rights, finalization, mixing, counting, publication, and record retention, with forms replacing the register of voters.",
  },
  {
    law: "RP Act 1950, s.23(5) and Registration of Electors Rules (Form 6B)",
    now: "Electors may give their Aadhaar number to link it to the roll. The Commission told the Supreme Court in 2023 that this is voluntary.",
    needed: "Because linking is voluntary, Aadhaar cannot be the only way to vote online. A non-Aadhaar route (here PAN plus roll-mobile OTP plus face match, and always the polling station) must stay available.",
  },
  {
    law: "Aadhaar Act, 2016, and the Aadhaar Authentication for Good Governance Rules, 2020 (amended 31 January 2025)",
    now: "Only authorised entities may perform Aadhaar authentication; the 2025 amendment lets the Central Government approve more entities and purposes, after UIDAI review. Storing and sharing Aadhaar numbers is restricted.",
    needed: "An express authorisation for the election authority to authenticate electors for voting, meeting the proportionality test of K.S. Puttaswamy (2017, 2018): a law, a legitimate aim, necessity and safeguards.",
  },
  {
    law: "Income-tax Act, 2025 (in force from 1 April 2026)",
    now: "PAN is issued and verified for tax purposes; existing PANs remain valid. Online PAN verification is available to listed categories of entities.",
    needed: "A legal basis and an arrangement with the Income Tax Department to verify PAN details for elector registration, limited to that purpose.",
  },
  {
    law: "Digital Personal Data Protection Act, 2023, and DPDP Rules, 2025 (notified 13 November 2025; main obligations phased in to May 2027)",
    now: "Personal data must be processed lawfully, for a stated purpose, with security safeguards and breach notification; the State may be exempted for notified purposes.",
    needed: "Either full compliance (notice, purpose limitation, retention limits, breach reporting) or a narrow, notified exemption for electoral processing, plus rules on how long identity linkage is kept after the election.",
  },
  {
    law: "Information Technology Act, 2000 (s.70) and CERT-In directions",
    now: "Systems can be declared protected Critical Information Infrastructure; incidents must be reported to CERT-In.",
    needed: "Declare the election system a protected system, require independent security testing and incident reporting, and allow responsible disclosure by researchers.",
  },
  {
    law: "Bharatiya Nyaya Sanhita, 2023, Chapter IX (ss.169–177)",
    now: "Election offences: bribery, undue influence, personation.",
    needed: "Clear offences for remote voting: watching or demanding to see someone vote online, buying, selling or taking voting phones or registrations, and tampering with election servers, keys or records.",
  },
  {
    law: "Certification and observers (no statute today)",
    now: "EVMs are designed and certified by public-sector manufacturers and a technical expert committee.",
    needed: "Public certification criteria, independent audits, published source code and verifier, and a statutory right for candidates, parties and accredited observers to obtain the record and verify it.",
  },
];

export function Law() {
  return (
    <main className="page">
      <h1>The law that would be needed</h1>
      <p className="lede">
        Software readiness is not legal authority. In India, only the Election Commission (for Parliament, State legislatures and the offices of President
        and Vice-President) or a State Election Commission (for panchayats and municipalities) can decide how votes are cast, and only under laws made by
        Parliament or a State legislature. Today no law provides for voting over the internet in those elections.
      </p>
      <p className="note">
        This is an orientation for discussion, not legal advice. Check the current text of every provision with qualified counsel before relying on it.
      </p>

      <h2>What would have to change</h2>
      <div className="table-wrap">
        <table className="methods-table">
          <thead>
            <tr>
              <th scope="col">Law</th>
              <th scope="col">What it says now</th>
              <th scope="col">What it would need to say</th>
            </tr>
          </thead>
          <tbody>
            {ROWS.map((r) => (
              <tr key={r.law}>
                <th scope="row">{r.law}</th>
                <td>{r.now}</td>
                <td>{r.needed}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2>Context from the courts and recent practice</h2>
      <ul>
        <li>
          <b>Association for Democratic Reforms v. Election Commission of India</b> (Supreme Court, 26 April 2024) refused a return to paper ballots and a
          100% VVPAT count, and let the second- and third-placed candidates ask, within seven days, for engineers to check the memory of 5% of EVMs in a
          constituency. An online system would need at least the same: any candidate can re-verify the whole count.
        </li>
        <li>
          <b>K.S. Puttaswamy</b> (2017, 2018) requires any use of Aadhaar or personal data by the State to be backed by law, necessary and proportionate.
        </li>
        <li>
          <b>PUCL v. Union of India</b> (2013) gave voters the right to reject all candidates (NOTA), which this system keeps on every ballot.
        </li>
        <li>
          The Bihar State Election Commission piloted mobile-app voting for some municipal by-elections in 2025, under state law, for a registered subset of
          voters. That is a local-body pilot, not a change to how Lok Sabha or Assembly elections are held.
        </li>
      </ul>

      <h2>Rules this design already respects</h2>
      <ul>
        <li>One counted vote per elector, in one constituency (s.62), with revoting defined so that only the last ballot counts.</li>
        <li>No single official can link a voter to a vote (s.128): votes are decrypted only as totals, by a threshold of trustees using hardware.</li>
        <li>Ties are reported, never broken by software (s.65).</li>
        <li>NOTA on every ballot; counted, cannot win.</li>
        <li>Synthetic data only: no real roll, Aadhaar, PAN, phone number or photograph is used anywhere in this project.</li>
      </ul>

      <h2>Sources</h2>
      <ul className="sources">
        <li>
          <a href="https://www.indiacode.nic.in/bitstream/123456789/2096/1/Rp1951.pdf">Representation of the People Act, 1951 (India Code)</a>
        </li>
        <li>
          <a href="https://khaitanco.com/thought-leadership/Aadhaar-authentication-for-private-entities">Khaitan &amp; Co: Aadhaar authentication amendment rules, 2025</a>
        </li>
        <li>
          <a href="https://www.drishtiias.com/daily-updates/daily-news-analysis/eci-clarifies-aadhaar-linkage-with-electoral-roll-is-voluntary">ECI clarifies Aadhaar linkage is voluntary (2023)</a>
        </li>
        <li>
          <a href="https://www.businesstoday.in/personal-finance/tax/story/income-tax-act-2025-no-need-to-reapply-for-pan-existing-pans-remain-valid-cbdt-clarifies-539544-2026-06-29">Income-tax Act 2025: existing PANs remain valid</a>
        </li>
        <li>
          <a href="https://tinpan.proteantech.in/services/online-pan-verification/pan-verification-overview.html">Protean: Online PAN Verification</a>
        </li>
        <li>
          <a href="https://www.azbpartners.com/bank/indias-digital-personal-data-protection-act-phased-rollout-and-key-compliance-milestones/">AZB &amp; Partners: DPDP Act phased rollout</a>
        </li>
        <li>
          <a href="https://www.scobserver.in/reports/vvpat-vote-verification-judgement-summary/">Supreme Court Observer: VVPAT judgment summary (2024)</a>
        </li>
      </ul>
    </main>
  );
}
