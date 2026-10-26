"""Plainly - Confusing notices, explained in plain language.

Run:  streamlit run app.py
"""
import html
import io
import json
import os
import re

import streamlit as st
from google import genai
from google.genai import types
from pypdf import PdfReader

from scam_scanner import scan, level_for

# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------
st.set_page_config(page_title="Plainly", page_icon="🔍", layout="centered")

DEFAULT_MODEL = "gemini-2.5-flash"
# Keep fallback attempts limited to model-availability errors. Quota/auth errors
# should stop immediately, otherwise fallback calls waste the remaining quota.
FALLBACK_MODELS = ["gemini-2.0-flash", "gemini-flash-latest"]

LANGUAGES = {
    "English": "simple English",
    "हिन्दी (Hindi)": "simple Hindi written in Devanagari script",
    "ਪੰਜਾਬੀ (Punjabi)": "simple Punjabi written in Gurmukhi script",
}

SAMPLES = {
    "📩 Sample: fake bank SMS": (
        "Dear Customer, your SBI account will be BLOCKED within 24 hours due to pending KYC. "
        "Update immediately at http://sbi-kyc-update.xyz/login and share the OTP you receive to avoid "
        "suspension. Call +91 98765 43210 for help."
    ),
    "📄 Sample: electricity bill notice": (
        "NOTICE OF DISCONNECTION. Consumer No. 4471820. Pursuant to Section 56 of the Electricity Act, "
        "the outstanding amount of Rs. 3,240 for the billing period ending 30 September 2026 remains "
        "unpaid. Failure to remit the said dues on or before 15 November 2026 shall render your "
        "connection liable to disconnection and a reconnection fee of Rs. 500. Pay online at "
        "https://pspcl.in or at any authorised collection centre. Ignore if already paid."
    ),
}

SYSTEM_PROMPT = """You are Plainly, a careful assistant that helps ordinary people understand \
confusing notices, bank/government/legal/medical letters and suspicious messages.

Rules:
- Explain in {language}. Use short sentences and everyday words a 12-year-old can follow.
- Keep every amount, date, name, reference number and deadline EXACTLY as written. Never invent facts.
- If something is missing or unclear, say so instead of guessing.
- Be honest about scam risk. Genuine notices can also sound strict; judge by the whole picture.
- You are not a lawyer or financial advisor. Encourage verifying through official channels.

Return ONLY a JSON object with these keys:
{{
  "extracted_text": "the full original text of the notice (copy it from the input/image exactly)",
  "doc_type": "short label, e.g. Bank SMS, Electricity bill notice, Court summons",
  "summary": "2-3 sentence plain explanation of what this is",
  "what_they_want": "what the sender wants you to do, in one or two sentences",
  "deadline": "the key deadline exactly as given, or 'No deadline found'",
  "if_ignored": "what may happen if you do nothing, or 'Not stated'",
  "steps": ["3 to 5 short, concrete next steps in order"],
  "scam_risk": "low | medium | high",
  "scam_reasoning": "1-3 sentences explaining the risk level in plain words",
  "safe_advice": "one sentence on how to verify this safely (e.g. call the number on the official website or card)"
}}
Write every value (except extracted_text and scam_risk) in {language}. scam_risk must be exactly low, medium or high in English."""


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def get_api_key() -> str:
    key = st.session_state.get("api_key_input", "").strip()
    if key:
        return key
    try:
        if "GEMINI_API_KEY" in st.secrets:
            return st.secrets["GEMINI_API_KEY"]
    except Exception:
        pass
    return os.environ.get("GEMINI_API_KEY", "")


def read_pdf_text(data: bytes) -> str:
    try:
        reader = PdfReader(io.BytesIO(data))
        return "\n".join((p.extract_text() or "") for p in reader.pages).strip()
    except Exception:
        return ""


def parse_json(raw: str) -> dict:
    raw = (raw or "").strip()
    raw = re.sub(r"^```(?:json)?|```$", "", raw, flags=re.MULTILINE).strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", raw, flags=re.DOTALL)
        if match:
            return json.loads(match.group(0))
        raise


def _friendly_api_error(exc: Exception) -> str:
    """Convert common Gemini API failures into actionable, user-friendly messages."""
    message = str(exc)
    lower = message.lower()

    if "resource_exhausted" in lower or "quota" in lower or "429" in lower:
        return (
            "Gemini API quota limit reached. This is not usually a bug in Plainly. "
            "Check your usage/limits in Google AI Studio, then wait until the quota resets. "
            "Trying another model may not help if the project-level limit is exhausted."
        )
    if "api_key_invalid" in lower or "invalid api key" in lower or "api key not valid" in lower or "401" in lower:
        return "The Gemini API key was rejected. Check that you copied the key correctly and that it is active."
    if "permission_denied" in lower or "403" in lower:
        return "Google rejected this request because the key/project may not have permission to use the API. Check the key's project and API access."
    if "not_found" in lower or "404" in lower or "unsupported model" in lower:
        return "The selected Gemini model may not be available to this API key. Try a supported model name in the sidebar."
    if "timed out" in lower or "timeout" in lower:
        return "The request timed out. Check your connection and try again."
    if "connection" in lower or "network" in lower:
        return "Could not connect to Gemini. Check your internet connection and try again."
    return "Gemini could not analyse this input. Check the technical details for the API error."


def analyse(client, model, language_desc, text=None, file_bytes=None, mime=None):
    """Send a notice to Gemini, using fallback models only when appropriate."""
    system = SYSTEM_PROMPT.format(language=language_desc)
    parts = []
    if file_bytes is not None:
        parts.append(types.Part.from_bytes(data=file_bytes, mime_type=mime))
        parts.append("Analyse this document.")
    else:
        parts.append(f"Analyse this notice:\n\n\"\"\"\n{text}\n\"\"\"")

    config = types.GenerateContentConfig(
        system_instruction=system,
        response_mime_type="application/json",
        temperature=0.2,
    )

    requested_model = (model or DEFAULT_MODEL).strip() or DEFAULT_MODEL
    models_to_try = [requested_model] + [m for m in FALLBACK_MODELS if m != requested_model]
    tried, last_err = [], None

    for candidate in models_to_try:
        try:
            response = client.models.generate_content(
                model=candidate, contents=parts, config=config
            )
            result = parse_json(response.text)
            if not isinstance(result, dict):
                raise ValueError("Gemini returned JSON, but it was not a JSON object.")
            # Make sure the most important display fields have safe defaults.
            result.setdefault("steps", [])
            if not isinstance(result.get("steps"), list):
                result["steps"] = []
            result.setdefault("scam_risk", "medium")
            if str(result.get("scam_risk", "")).lower() not in {"low", "medium", "high"}:
                result["scam_risk"] = "medium"
            return result
        except Exception as exc:
            tried.append(candidate)
            last_err = exc
            error_text = str(exc).lower()
            # Do not burn more requests on quota, auth, permission, or connectivity errors.
            stop_now = any(token in error_text for token in (
                "resource_exhausted", "quota", "429", "api_key_invalid",
                "invalid api key", "api key not valid", "401", "permission_denied",
                "403", "timed out", "timeout", "connection", "network",
            ))
            if stop_now:
                raise RuntimeError(_friendly_api_error(exc)) from exc
            # Only attempt another model for model-specific availability errors.
            model_error = any(token in error_text for token in (
                "not_found", "404", "unsupported model", "model is not available",
                "model not found",
            ))
            if not model_error:
                raise RuntimeError(_friendly_api_error(exc)) from exc

    raise RuntimeError(
        f"None of the configured models worked ({', '.join(tried)}). "
        f"{_friendly_api_error(last_err or Exception('Unknown error'))}"
    )


def risk_color(level: str) -> str:
    return {"Low": "#16a34a", "Medium": "#d97706", "High": "#dc2626"}[level]


def llm_score(level: str) -> int:
    return {"low": 10, "medium": 50, "high": 85}.get(str(level).lower().strip(), 50)


# ----------------------------------------------------------------------------
# Styling
# ----------------------------------------------------------------------------
st.markdown(
    """
<style>
html, body, [class*="css"] { font-size: 18px; }
.block-container { padding-top: 2rem; max-width: 780px; }
.badge { display:inline-block; padding:6px 16px; border-radius:999px; color:white;
         font-weight:700; font-size:1rem; }
.card { background: rgba(127,127,127,0.08); border-radius:14px; padding:16px 20px; margin:10px 0; }
.small { font-size:0.85rem; opacity:0.75; }
</style>
""",
    unsafe_allow_html=True,
)

# ----------------------------------------------------------------------------
# Sidebar
# ----------------------------------------------------------------------------
with st.sidebar:
    st.header("⚙️ Settings")
    st.text_input("Gemini API key", type="password", key="api_key_input",
                  help="Get a free key at aistudio.google.com")
    model_name = st.text_input(
        "Model", value=DEFAULT_MODEL,
        help="Leave the default unless you know a different model is available to your API key.",
    ).strip() or DEFAULT_MODEL
    st.markdown("---")
    st.markdown(
        "**Plainly** explains confusing notices in plain language and checks them for scam signals.\n\n"
        "<span class='small'>Plainly is a helper, not a lawyer or financial advisor. "
        "Always verify important notices through official channels.</span>",
        unsafe_allow_html=True,
    )

# ----------------------------------------------------------------------------
# Main UI
# ----------------------------------------------------------------------------
st.title("🔍 Plainly")
st.caption("Confusing notices, explained in plain language.")

lang_label = st.selectbox("Explain in", list(LANGUAGES.keys()))
language_desc = LANGUAGES[lang_label]

st.session_state.setdefault("notice_text", "")


def load_sample(text):
    st.session_state["notice_text"] = text


tab_text, tab_file = st.tabs(["✍️ Paste text", "📷 Upload photo / PDF"])

with tab_text:
    cols = st.columns(len(SAMPLES))
    for col, (label, sample) in zip(cols, SAMPLES.items()):
        col.button(label, on_click=load_sample, args=(sample,), use_container_width=True)
    st.text_area("Paste the notice, SMS or email here", key="notice_text", height=200,
                 placeholder="Paste any bank letter, government notice, bill, or suspicious message...")

with tab_file:
    uploaded = st.file_uploader("Upload a photo of the notice or a PDF",
                                type=["png", "jpg", "jpeg", "webp", "pdf"])
    if uploaded is not None and uploaded.type.startswith("image/"):
        st.image(uploaded, caption="Your upload", use_container_width=True)

go = st.button("✨ Explain it to me", type="primary", use_container_width=True)

# ----------------------------------------------------------------------------
# Run analysis
# ----------------------------------------------------------------------------
if go:
    api_key = get_api_key()
    pasted = st.session_state.get("notice_text", "").strip()

    if not api_key:
        st.error("Please add your Gemini API key in the sidebar (left side). "
                 "On a phone, tap the arrow at the top-left.")
        st.stop()
    if not pasted and uploaded is None:
        st.warning("Paste some text or upload a photo/PDF first.")
        st.stop()

    try:
        client = genai.Client(api_key=api_key)
    except Exception as e:
        st.error(_friendly_api_error(e))
        with st.expander("Technical details"):
            st.code(str(e))
        st.stop()

    try:
        with st.spinner("Reading and checking your notice..."):
            if pasted:
                data = analyse(client, model_name, language_desc, text=pasted)
            else:
                raw = uploaded.getvalue()
                if uploaded.type == "application/pdf":
                    pdf_text = read_pdf_text(raw)
                    if len(pdf_text) > 40:
                        data = analyse(client, model_name, language_desc, text=pdf_text)
                    else:  # scanned PDF -> let Gemini read it directly
                        data = analyse(client, model_name, language_desc,
                                       file_bytes=raw, mime="application/pdf")
                else:
                    data = analyse(client, model_name, language_desc,
                                   file_bytes=raw, mime=uploaded.type)
    except Exception as e:
        st.error(str(e) if isinstance(e, RuntimeError) else _friendly_api_error(e))
        with st.expander("Technical details"):
            st.code(str(e))
        st.stop()

    # Scam check: rules + AI judgement
    source_text = pasted or data.get("extracted_text", "")
    rules = scan(source_text)
    final = round(0.4 * rules["score"] + 0.6 * llm_score(data.get("scam_risk", "medium")))
    level = level_for(final)

    # ---------------- Results ----------------
    st.markdown("---")
    st.subheader(f"📌 {data.get('doc_type', 'Notice')}")

    summary = html.escape(str(data.get("summary", "")))
    st.markdown(f"<div class='card'>{summary}</div>", unsafe_allow_html=True)

    c1, c2 = st.columns(2)
    what_they_want = html.escape(str(data.get("what_they_want", "-")))
    deadline = html.escape(str(data.get("deadline", "-")))
    if_ignored = html.escape(str(data.get("if_ignored", "-")))
    c1.markdown(f"<div class='card'><b>🎯 What they want</b><br>{what_they_want}</div>",
                unsafe_allow_html=True)
    c2.markdown(f"<div class='card'><b>⏰ Deadline</b><br>{deadline}</div>",
                unsafe_allow_html=True)
    st.markdown(f"<div class='card'><b>⚠️ If ignored</b><br>{if_ignored}</div>",
                unsafe_allow_html=True)

    st.subheader("🛡️ Scam check")
    st.markdown(
        f"<span class='badge' style='background:{risk_color(level)}'>{level} risk · {final}/100</span>",
        unsafe_allow_html=True,
    )
    st.progress(final / 100)
    st.write(str(data.get("scam_reasoning", "")))

    if rules["flags"]:
        st.markdown("**Red flags found:**")
        for f in rules["flags"]:
            st.markdown(f"- 🚩 **{f['name']}**: {f['why']}")
    else:
        st.markdown("No common scam patterns found in the text.")
    for s in rules["safe_signals"]:
        st.markdown(f"- ✅ {s}")

    st.info(f"🔐 {data.get('safe_advice', 'Verify through the official website or helpline.')}")

    st.subheader("✅ What to do next")
    for i, step in enumerate(data.get("steps", []), 1):
        st.checkbox(step, key=f"step_{i}")

    with st.expander("See the original text"):
        st.text(source_text)

    st.caption("Plainly is a helper, not a lawyer or financial advisor. "
               "Verify important notices through official channels.")
