# recce ⇄ Sköll-Fieldkit — feed exploitation, fold findings back in

recce is the **enumeration + reporting** half of an engagement; the
[**Sköll-Fieldkit**](https://github.com/dloucks01/skoll-fieldkit) is the **exploitation** half
(initial access → privesc → reporting, generators that *print* the commands you paste). recce
round-trips with it, so you enumerate once and let each side feed the other:

```
recce enum/vulns ──skoll-export──▶  Sköll sweep + generators  ──findings.json──▶ gen_report
       ▲                                                                              │
       └──────────────  recce skoll-import  ◀── gen_report.py --export-recce ─────────┘
        (proven findings land back in the recce workbook + report)
```

Both directions are **offline, deterministic, stdlib-only** — same airgap contract as the rest of
recce. Two commands:

| Command | Direction | What it does |
|---|---|---|
| `recce skoll-export -o eng` | recce → Sköll | writes `eng/skoll/` — a ready attack plan Sköll consumes |
| `recce skoll-import <file> -o eng` | Sköll → recce | folds a Sköll `findings.json` (proven exploitation) back into the workbook + report |

## recce → Sköll — seed the attack

After `enum`/`vulns`:

```bash
recce skoll-export -o eng          # -> eng/skoll/{recce-bridge.json, ports.gnmap, smb-null.txt, SKOLL.md}
```

- **`SKOLL.md`** — a human, severity-ranked "run **this** generator on **that** host, because …"
  plan. Read this first.
- **`recce-bridge.json`** — the rich machine feed: each host's open ports, service/version, recce's
  **confirmed** findings, and the suggested Sköll generator. In the Sköll checkout:
  `python3 access/network/sweep.py triage --recce recce-bridge.json` ranks every host and floats
  proven quick-wins to the top.
- **`ports.gnmap`** / **`smb-null.txt`** — an nmap-greppable + netexec-style handoff for Sköll's
  classic `sweep.py triage --nmap … --nxc …` path (works with an unmodified Sköll).

## Sköll → recce — fold proven findings back into the sheet + report

When the Sköll operator has proven findings and written them up, they export the recce feed:

```bash
# (in the Sköll checkout)
python3 report/gen_report.py findings.json --export-recce   # -> recce_findings.json (KB-enriched)
```

Then fold it into this engagement:

```bash
recce skoll-import recce_findings.json -o eng
```

Each proven finding becomes a **confirmed** vulnerability (source `skoll`) on its host and shows up in
the **Vulnerabilities** sheet, the report, and the DOCX write-ups; the host is marked *access-gained*
and ticks the Checklist **Access** step. Re-importing is idempotent (deduped by title + host).

recce also imports a **raw** `findings.json` (without the `--export-recce` enrichment) — it uses each
finding's own `severity` and parses the host from `affected_host`; the enriched export just adds the
accurate CWE/remediation from Sköll's knowledge base.

> One source of truth: recce's workbook now tracks both coverage (what was enumerated) and outcomes
> (what Sköll proved). See the full round-trip guide in the Sköll repo's `INTEGRATION.md`.
