# OATH Receipt Explorer

Static site for inspecting signed `Notarized<T>` envelopes from OATH sample
runs. It is a convenience viewer only; verification still happens locally with
the OATH verifier and the original evidence bytes.

## Contents

- `index.html` - single-page layout
- `styles.css` - receipt-explorer styling
- `app.js` - envelope cards, detail modal, copy-to-clipboard behavior
- `data.js` - generated envelope payload from `logs/sample-run/dlc-sample-run.jsonl`

No backend. No build step. No npm. Pure HTML, CSS, and JavaScript.

## Regenerate Data

After running a fresh sample export:

```bash
python scripts/export_sample_run.py
bash web/build-data.sh
```

## Run Locally

```bash
cd web
python3 -m http.server 8765
```

Open `http://127.0.0.1:8765`.

## Deploy

The site works on any static host:

```bash
wrangler pages deploy ./web --project-name=oath-receipt-explorer
```

GitHub Pages, Netlify, and other static hosts work as well.
