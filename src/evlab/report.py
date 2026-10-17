"""Static observer report: one self-contained, accessible HTML page built from
the independent verifier's JSON report. No JavaScript, no external requests,
semantic tables, readable without colour."""

from __future__ import annotations

import html
import json
from pathlib import Path

CSS = """
:root{--bg:#fbfaf7;--fg:#1d1d1b;--mute:#5f5d57;--line:#d9d6cf;--ok:#1f6f43;--bad:#a12622;--warn:#8a5a00;--card:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--fg:#ecebe6;--mute:#a3a19a;--line:#34332f;--ok:#6fcf97;--bad:#ff8a80;--warn:#f2c14e;--card:#1c1c1a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:980px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:1.7rem;margin:.2em 0}h2{font-size:1.2rem;margin:2em 0 .6em;border-bottom:1px solid var(--line);padding-bottom:.3em}
.notice{border:2px solid var(--warn);padding:12px 14px;border-radius:6px;background:var(--card)}
.status{display:inline-block;font-weight:700;padding:4px 10px;border-radius:4px;border:2px solid currentColor}
.PASS,.VERIFIED{color:var(--ok)}.FAIL,.NOT{color:var(--bad)}.WARN{color:var(--warn)}
table{width:100%;border-collapse:collapse;margin:.5em 0;background:var(--card)}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:.85rem;color:var(--mute);font-weight:600}td.num{text-align:right;font-variant-numeric:tabular-nums}
code{font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
.meta{color:var(--mute);font-size:.9rem}.bar{height:8px;background:var(--fg);opacity:.75;border-radius:2px}
"""


def render(report: dict) -> str:
    f = report["facts"]
    e = html.escape
    st = report["status"]
    out = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>Observer Report</title><style>{CSS}</style></head><body><main>",
        f"<p class='notice' role='note'><strong>Synthetic research data.</strong> {e(f.get('notice', ''))}</p>",
        f"<h1>{e(f.get('title', 'Election record'))}</h1>",
        f"<p class='meta'>Election <code>{e(f.get('election_id', '?'))}</code> &middot; manifest <code>{e(f.get('manifest_hash', '?'))}</code></p>",
        f"<p>Independent verification: <span class='status {st.split()[0]}'>{e(st)}</span> "
        f"&mdash; {report['failures']} failures, {report['warnings']} warnings, {len(report['checks'])} checks.</p>",
        f"<p class='meta'>Final signed checkpoint root <code>{e(str(f.get('final_root')))}</code> over {f.get('entries')} entries.</p>",
    ]
    out.append("<h2>Results by constituency</h2>")
    for cid, r in sorted(report["results"].items()):
        if "counts" not in r:
            continue
        total = max(1, r["ballots"])
        out.append(f"<h3>{e(r['name'])} <span class='meta'>({e(cid)})</span></h3>")
        out.append(
            f"<p class='meta'>{r['ballots']} ballots &middot; {r.get('credentials_issued', '?')} credentials issued &middot; "
            f"{r.get('eligible', '?')} eligible &middot; decrypted by trustees {', '.join(map(str, r['quorum']))}</p>"
        )
        out.append(
            "<table><thead><tr><th scope='col'>Option</th><th scope='col'>Votes</th><th scope='col'>Share</th>"
            "<th scope='col' aria-hidden='true'></th></tr></thead><tbody>"
        )
        for oid, v in sorted(r["counts"].items(), key=lambda kv: -kv[1]):
            mark = " (winner)" if oid == r.get("winner") else (" (tied)" if oid in r.get("tied", []) else "")
            pct = 100 * v / total
            out.append(
                f"<tr><td>{e(r['options'].get(oid, oid))}{mark}</td><td class='num'>{v}</td><td class='num'>{pct:.1f}%</td>"
                f"<td aria-hidden='true' style='width:30%'><div class='bar' style='width:{pct:.1f}%'></div></td></tr>"
            )
        out.append("</tbody></table>")
        if r.get("tied"):
            out.append(
                "<p><strong>Tie.</strong> Not resolved by software. Under s.65 of the Representation of the People Act, 1951 "
                "the Returning Officer decides by lot.</p>"
            )
        if r.get("nota_exceeds_winner"):
            out.append("<p>NOTA received more votes than the winning candidate. NOTA cannot win under the rule this simulation uses.</p>")
    out.append(
        "<h2>Verification checks</h2><table><thead><tr><th scope='col'>Result</th><th scope='col'>Check</th><th scope='col'>Detail</th></tr></thead><tbody>"
    )
    for c in report["checks"]:
        out.append(
            f"<tr><td class='{c['status']}'><strong>{c['status']}</strong></td><td>{e(c['title'])}<br><code>{e(c['id'])}</code></td>"
            f"<td>{e(c['detail'])}</td></tr>"
        )
    out.append("</tbody></table>")
    rj = f.get("rejections_by_reason") or {}
    if rj:
        out.append("<h2>Ballots rejected by the ballot box</h2><table><thead><tr><th scope='col'>Reason</th><th scope='col'>Count</th></tr></thead><tbody>")
        out += [f"<tr><td><code>{e(k)}</code></td><td class='num'>{v}</td></tr>" for k, v in sorted(rj.items())]
        out.append("</tbody></table>")
    sw = f.get("software", {})
    out.append(f"<p class='meta'>Software {e(sw.get('name', ''))} {e(sw.get('version', ''))}, source digest <code>{e(sw.get('source_digest', ''))}</code>.</p>")
    out.append("</main></body></html>")
    return "\n".join(out)


def write_report(report_json: Path, out_html: Path) -> None:
    out_html.write_text(render(json.loads(Path(report_json).read_text())), encoding="utf-8")
