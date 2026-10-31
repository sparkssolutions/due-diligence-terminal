# Due Diligence Terminal

A standalone web-based research terminal for conducting due diligence on prediction markets. Features a dark terminal-style UI with real-time charting and market analysis tools.

## Features

- **Terminal UI** — dark-themed interface inspired by Bloomberg Terminal and trading platforms
- **Chart.js integration** — interactive price and probability charts
- **Standalone worker** — runs analysis computations in a Web Worker for non-blocking performance
- **Polymarket integration** — market data analysis and probability tracking
- **Offline capable** — single HTML file bundles everything needed

## Architecture

```
terminal.html         — main UI (self-contained HTML + CSS + JS)
worker.js             — Web Worker for background computations
standaloneworker.js   — bundled standalone worker build
build_standalone.py   — build script to bundle worker into standalone
_polytest.js          — test harness for Polymarket API integration
```

## Usage

Open `terminal.html` in any modern browser — no server required.

## Built With

- Vanilla JavaScript
- Chart.js
- Web Workers API
- CSS custom properties design system
