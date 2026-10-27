# UI smoke test (mock mode)

`smoke.py` drives the desktop UI in the browser against `preview.sh` +
`mock.js`: the protected core flow (URL → 진단 시작 → 결과 리포트) plus the
UX behaviors around it (live filter, tail-follow, quick chips, chat markdown,
Enter-to-diagnose, Esc-to-close, toast). Fails on any console error or any
blocking `alert()` dialog.

Requires Playwright + Chromium (external tooling, nothing added to the repo):

```bash
pip install playwright && playwright install chromium
cd redcell-desktop && ./preview.sh start
python3 ui/tests/smoke.py            # REDCELL_PREVIEW_URL to override
```
