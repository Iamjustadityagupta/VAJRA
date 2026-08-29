# VAJRA Lightweight Demo

A working proof-of-concept for the finalized AI Kavach concept: Safe Clone → Discover → Reproduce → Reason → Patch → Attack → Verify → Rescan.

## Run

### Backend
```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Semgrep is optional. If installed, VAJRA uses it; otherwise the included deterministic fallback scanner detects the demo SQL injection.

### Frontend
```bash
cd frontend
npm install
npm run dev
```

## Demo target
Zip the contents of `target_app/` and upload the zip in the UI. The target intentionally contains a SQL injection for demonstration purposes.
