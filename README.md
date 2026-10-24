# ChangeRadar

AI-assisted code change risk analyzer built with Flask, SQLAlchemy, SQLite, vanilla JavaScript, and the Gemini API.

## Features
- Paste a Git diff or upload `.diff`, `.patch`, or `.txt`
- Deterministic rule checks for credential-like assignments, `eval`/`exec`, `shell=True`, dynamic SQL, debug mode, broad exceptions, disabled TLS verification, and TODO/FIXME markers
- Transparent heuristic risk score (0–100)
- Optional Gemini review summary, extra findings, and test suggestions
- Persistent report history, report details, and delete action
- Rule-based analysis still works when Gemini is not configured or unavailable

## Setup (Windows PowerShell)
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
notepad .env
python app.py
```

Add your Gemini API key to `.env`:
`GEMINI_API_KEY=your_actual_key`

Then open http://127.0.0.1:5000

If PowerShell blocks activation, use:
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

## Quick smoke tests
- Click the `⌘` button to load the sample diff, then click Analyze changes.
- Open Report history to confirm the report was saved.
- Try a tiny diff with `debug = True` or `eval(value)` and confirm a finding appears.
- Open `http://127.0.0.1:5000/api/health` to check whether the server sees the API key.

## API
- `GET /api/health`
- `POST /api/analyze` (multipart form: `diff_text`, optional `title`, optional `diff_file`)
- `GET /api/reports`
- `GET /api/reports/<id>`
- `DELETE /api/reports/<id>`

## Limitations
This is a portfolio MVP, not a security scanner or a replacement for human code review. Rules are heuristic and can miss issues or flag safe code. The current risk score is an explainable demo heuristic, not a calibrated probability. The diff text is sent to Google Gemini when AI review is configured; do not submit proprietary code or secrets without permission. Use a `.env` file and never commit API keys.
