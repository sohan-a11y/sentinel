# Run the Sentinel CLI Demo

Sentinel is **CLI-first**. There is no dashboard required for this project demo.

There are two double-click launchers:

| Launcher | Use it for |
|---|---|
| [`Start Sentinel Demo.cmd`](../../Start%20Sentinel%20Demo.cmd) | A fully local demo without AI. |
| [`Start Sentinel AI Demo.cmd`](../../Start%20Sentinel%20AI%20Demo.cmd) | The two-minute demo with real TokenRouter AI triage. |

## One-time AI setup

Do this only for the AI launcher. Keep the API key on your computer; never paste it into a
terminal recording, source code, report, or chat.

1. Rotate any key that was ever pasted into chat or a screen recording.
2. Double-click [`Start Sentinel AI Demo.cmd`](../../Start%20Sentinel%20AI%20Demo.cmd).
3. If the key is not already in your local environment, the launcher asks for it with hidden input.
   Paste it there; it is passed only to that demo process and is not saved or displayed.

If you prefer a non-interactive setup, copy `.env.example` to `.env` and add:

```env
SENTINEL_TOKENROUTER_API_KEY=your_new_key_here
SENTINEL_TOKENROUTER_BASE_URL=https://api.tokenrouter.com/v1
SENTINEL_TOKENROUTER_MODEL=z-ai/glm-5.2-free
```

The launcher creates the local Python environment automatically the first time. Run it once before
recording the video so the package-installation wait is not part of the two minutes.

## What happens in the AI demo

The launcher automatically creates a tiny HTTPS site at `https://127.0.0.1`. That is your own
computer, not a customer site. Sentinel then:

1. Proves control of that disposable local site.
2. Creates a short, auditable permission contract.
3. Performs the real `recon.v1` workflow against the local site.
4. Sends a **synthetic local site-map summary only** to TokenRouter for a six-CWE AI triage preview.
5. Shows status, coverage, AI triage, findings, and audit integrity in the CLI.

The AI summary contains local page addresses, page/form counts, technology labels, endpoint methods,
parameter names, and cookie names from the synthetic demo. It does **not** include a customer target,
real credential, request body, database record, session token, or API secret.

The CLI says AI triage is complete only after Sentinel receives and validates an actual model response.
If the selected model returns invalid structured output or the service is unavailable, Sentinel labels
the work as manual triage instead of pretending AI succeeded.

## What the CLI controls mean

| Key | Meaning |
|---|---|
| `Enter` | Refresh status. |
| `H` | Stop the current local run. |
| `R` | Save a local Markdown report. |
| `Q` | Close the demo. |

The report and local audit log are stored beneath `.sentinel-demo` in this project. The ignored run
folder also contains disposable TLS, proof, and canary files for this local fixture. They are not
customer data. Delete that exact run folder after you finish if you no longer need the demo artifacts.

## Honest scope statement for the demo

“This demo shows a local, contract-limited reconnaissance run with AI-assisted CWE triage. It does
not show active exploitation, proof of compromise, or a claim that any application is secure.”

Nuclei, ZAP active scan, IDOR testing, live verification, payload generation, and proof-of-concept
generation remain blocked in contract-backed runs. The external TokenRouter request in the AI mode is
only for the fixed synthetic local demo site map; it is not a customer-data workflow.

For the exact two-minute narration, use the [Demo Video Script](demo-video-script.md).
