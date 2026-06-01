# OATH Receipt Explorer — `web/`

Static SPA that lets anyone — judge, examiner, journalist — explore signed `Notarized<T>` envelopes from real OATH triage runs without installing anything.

**Live URL:** _set this at submission time after `wrangler pages deploy ./web`_

## What's in here

- `index.html` — single-page layout
- `styles.css` — dark forensic theme (gold accent / verified-green / quarantine-amber / ralph-purple)
- `app.js` — interactive layer: envelope cards, detail modal, copy-to-clipboard
- `data.js` — *generated* — the real envelope payload from `logs/sample-run/dlc-sample-run.jsonl`

No backend. No build step. No npm. Pure HTML/CSS/JS.

## Regenerate the data bundle

After running a fresh `python scripts/export_sample_run.py`, regenerate `web/data.js`:

```bash
bash web/build-data.sh
```

## Test locally

```bash
cd web && python3 -m http.server 8765
# open http://127.0.0.1:8765
```

## Deploy

The site is pure static — works on any host:

```bash
# Cloudflare Pages
wrangler pages deploy ./web --project-name=oath-receipt-explorer

# Or GitHub Pages (serve from /web subdir)
# Settings → Pages → Source: deploy from a branch · main · /web

# Or Netlify
netlify deploy --prod --dir=web
```

## Design notes

- The page is monochrome dark-graphite with a single warm-gold accent. Every other color signals a verdict state (green = VERIFIED, amber = QUARANTINED, purple = RALPH WIGGUM).
- Mobile-first: cards stack vertically below 720px; metrics column-stack below 720px; how-it-works grid stacks below 820px.
- Modal renders inline via `<template>`; no framework. Escape key closes.
- All envelope IDs are clickable for `oath verify` — the copy-to-clipboard JS makes the receipt one paste away.
