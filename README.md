# Automated Google Dorking & Exposure Detection Tool

A complete defensive security tool built for ethical auditing, OSINT research, and identifying accidentally exposed information on the public internet.

## 🚀 Features

- **Google Dorking**: Automatically fetch URLs using Google Custom Search API.
- **Selenium Scraping**: Headless browsing to fetch page content safely.
- **AI-Assisted Analysis**: Pattern detection for API keys, passwords, tokens, and sensitive files.
- **Risk Scoring**: Automated categorization (LOW/MEDIUM/HIGH) based on findings.
- **Reporting**: Export results to JSON and CSV formats.
- **Web UI**: Simple browser interface to control scans.

## ⚠️ Legal Disclaimer

This tool is for **authorized security auditing** only. Unauthorized scanning of third-party systems is illegal. Always obtain written permission before testing. Please read [LEGAL.md](LEGAL.md) for full terms.

## 🛠️ Installation

1. **Clone the project**
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Configure Environment**:
   - Rename `.env.example` to `.env`.
   - Add your `GOOGLE_API_KEY` and `GOOGLE_CSE_ID`.
   - Update `config.yaml` if needed.

## 🏃 Running the Tool

1. **Start the FastAPI Server**:
   ```bash
   python app.py
   ```
2. **Open the Web UI**:
   Navigate to `http://localhost:8000` in your browser.

3. **Perform a Scan**:
   - Upload a dork file or enter manual URLs.
   - Confirm authorization.
   - Click "Start Security Audit".

## 📂 Project Structure

- `app.py`: Main FastAPI server.
- `modules/`: Core logic for scraping, analysis, and reporting.
- `dorks/`: Storage for custom Google Dorks.
- `reports/`: Generated security reports.
- `frontend/`: Single-page UI.

## 🧪 Testing

Run unit tests using pytest:
```bash
pytest tests/test_analyzer.py
```

## 🛡️ Best Practices for Defense

- Ensure `.env` and `config` files are added to `.gitignore`.
- Use `robots.txt` to prevent indexing of sensitive directories.
- Implement proper authentication for all administrative panels.
- Regularly audit public exposure using tools like this one.
