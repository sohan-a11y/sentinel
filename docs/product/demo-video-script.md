# Sentinel: Exact Two-Minute AI Demo Script

Run [`Start Sentinel AI Demo.cmd`](../../Start%20Sentinel%20AI%20Demo.cmd) once before recording.
Then record one terminal window. Read one row during its allocated time: the complete script is
**2:00 minutes**. The narration is 233 words, paced at about 116–117 words per minute.

Never show the `.env` file, an API key, an audit file, or a raw AI response.

| Time | Show in the CLI | Say exactly this |
|---|---|---|
| 0:00–0:15 | Start screen: `SENTINEL — LOCAL DEMO STATUS`; target `127.0.0.1`. | “This is Sentinel: a command-line platform that makes security testing controlled and explainable. For this two-minute demonstration, it creates a disposable website only on this computer.” |
| 0:15–0:30 | `SCAN STATUS`; ownership and contract information. | “The target cannot be changed here. Sentinel proves control of the local site, creates a short permission contract, and limits the run to safe reconnaissance.” |
| 0:30–0:45 | `Allowed activity: recon.v1 only`; then `CWE COVERAGE`. | “That means it maps pages, forms, and security signals, but it does not run active exploit tools. The operator can still halt it at any time.” |
| 0:45–1:00 | `AI TRIAGE`: provider, model, and `synthetic local site map only`. | “This is the AI option. Sentinel sends only the synthetic local site map to TokenRouter, using the GLM model selected for this project. No customer system, API key, request body, or database record is involved.” |
| 1:00–1:15 | `AI-reviewed CWEs` and the status line. | “AI performs one narrow job: CWE relevance triage. It helps decide which weakness categories deserve an engineer’s review. It cannot choose a target, expand scope, or execute an exploit.” |
| 1:15–1:30 | Keep `AI TRIAGE` visible; refresh with `Enter` if it still says waiting. | “The screen labels the provider, requested model, data scope, and AI-reviewed CWE count. This status appears as completed only after Sentinel receives and validates a real AI response.” |
| 1:30–1:45 | `CWE COVERAGE`, `FINDINGS`, and `AUDIT LOG`. | “AI advice is not a confirmed vulnerability. Sentinel keeps suggestions separate from findings, records coverage, and preserves an audit trail. Zero findings is never presented as proof of security.” |
| 1:45–2:00 | The `R` and `H` controls. | “Finally, the operator can export a report or stop the run. Sentinel combines AI assistance with customer control: AI recommends what to review; the contract decides what the system may do.” |

## One-line business summary

“Sentinel uses AI to prioritize security review, while contracts and audit controls keep the customer
in charge of what the system can test.”

## Do not say

- “AI found a confirmed vulnerability” unless a separately verified finding is actually shown.
- “Zero findings means the website is secure.”
- “This runs active exploitation.”
- “Customer data is sent to TokenRouter.”
