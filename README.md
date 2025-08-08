# Privacy Leak Analyzer — Professional (Sample)

This improved "Pro" version includes a modern UI, progress feedback, logging, and PDF/JSON export.

## How to run

1. Create and activate a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # or venv\Scripts\activate on Windows
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the app from project root:
   ```bash
   python main.py
   ```

## Folder structure
- `main.py` — entry point (UI)
- `src/analyzer.py` — analysis logic (androguard)
- `src/report_generator.py` — PDF/JSON export helpers
- `reports/` — saved reports

Note: `androguard` installation may take time and has native dependencies. If you have issues, run `pip install androguard` alone and follow its errors.