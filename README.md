# 🔍 Plainly

**Confusing notices, explained in plain language.**

Plainly helps ordinary people understand bank letters, government notices, bills and suspicious
messages. Paste text or upload a photo/PDF and Plainly will:

- explain it in simple **English, Hindi or Punjabi**
- show **what they want from you, the deadline, and what happens if you ignore it**
- run a **scam check** (rule-based scanner + AI judgement) with a 0-100 risk score and red flags
- give a short **step-by-step checklist**

Built for NextSpark Hacks 2026.

## Run it locally

1. Install Python 3.10+
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Get a free Gemini API key from https://aistudio.google.com (Get API key).
4. Start the app:
   ```
   streamlit run app.py
   ```
5. Paste your API key in the sidebar (or set the `GEMINI_API_KEY` environment variable).

## Project structure

| File | Purpose |
|---|---|
| `app.py` | Streamlit UI and Gemini integration |
| `scam_scanner.py` | Rule-based scam signal scanner (regex) |
| `requirements.txt` | Python dependencies |

## Built with
Python, Streamlit, Google Gemini API, pypdf, Pillow, regex.
AI assistance: Claude (Anthropic) was used to help plan and write parts of the code.

## Disclaimer
Plainly is a helper, not a lawyer or financial advisor. Always verify important notices
through official channels.
