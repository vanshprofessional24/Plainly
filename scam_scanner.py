"""Plainly - rule-based scam scanner.

Looks for common scam signals in a notice / SMS and returns a 0-100 risk score
plus a list of human-readable red flags. Pure Python, no external dependencies.
"""
import re

# (name, regex, weight, explanation)
RULES = [
    ("Pressure / urgency",
     r"\b(immediately|urgent(ly)?|act now|last warning|final (notice|warning)|"
     r"within \d+ ?(hours?|hrs?|minutes?)|24 ?hours?|will be (blocked|suspended|deactivated|closed))\b",
     20, "Scammers rush you so you don't stop to think."),
    ("Asks you to share OTP / PIN / password",
     r"(share|send|provide|enter|tell|give|confirm|reply with).{0,30}\b(otp|pin|cvv|password|passcode)\b",
     35, "Real banks and offices never ask for your OTP, PIN or password."),
    ("Remote-access app mentioned",
     r"\b(anydesk|teamviewer|quicksupport|rustdesk)\b",
     35, "Installing these apps lets a scammer control your phone."),
    ("Gift card / crypto payment",
     r"\b(gift ?cards?|bitcoin|crypto(currency)?|usdt|google play card|itunes card)\b",
     30, "Official bodies do not ask for payment in gift cards or crypto."),
    ("Payment demand to a personal account / UPI",
     r"(pay|transfer|deposit|send).{0,40}\b(upi|wallet|fee|fine|penalty|processing charge|clearance)\b",
     15, "Check that any payment goes only to an official account."),
    ("Prize / lottery / reward claim",
     r"\b(you (have )?won|winner|lottery|lucky draw|congratulations|cashback|reward points?|claim your)\b",
     25, "Unexpected prizes are a classic scam hook."),
    ("KYC / account verification request",
     r"(\bkyc\b|update.{0,20}(pan|aadhaar|aadhar)|verify.{0,20}(account|identity|details)|account.{0,15}(blocked|suspended))",
     20, "Fake KYC messages are one of the most common frauds."),
    ("Shortened link",
     r"(bit\.ly|tinyurl|t\.co/|goo\.gl|cutt\.ly|rb\.gy|is\.gd|shorturl|tiny\.cc)",
     25, "Short links hide where you are really being sent."),
    ("Suspicious website ending",
     r"https?://\S+\.(xyz|top|click|work|loan|gq|tk|ml|cf|buzz|icu|monster)\b",
     25, "Unusual website endings are often used for fake sites."),
    ("Link without https",
     r"\bhttp://",
     10, "Official sites use secure (https) links."),
    ("Threat of arrest / police / court",
     r"\b(arrest(ed)?|warrant|cbi|customs|narcotics|digital arrest|police case)\b",
     20, "Real agencies do not threaten arrest over phone or SMS."),
    ("Asks you to call / WhatsApp an unknown number",
     r"\b(whatsapp|call|contact).{0,25}\+?\d[\d\s-]{8,}",
     15, "Verify numbers on the organisation's official website."),
    ("Generic greeting",
     r"\b(dear (customer|user|sir|madam|account holder|valued))\b",
     8, "Genuine notices usually use your actual name."),
]

# Signals that make a message look more genuine (reduce the score)
SAFE_RULES = [
    ("Warns you never to share OTP", r"(never|do not|don'?t) share.{0,30}(otp|pin|password)", 15),
    ("Government / official domain", r"\b[\w.-]+\.(gov\.in|nic\.in|gov|edu\.in|ac\.in)\b", 10),
]


def scan(text: str) -> dict:
    """Return {'score': int, 'level': str, 'flags': [...], 'safe_signals': [...]}."""
    t = (text or "").lower()
    flags, safe, score = [], [], 0

    for name, pattern, weight, why in RULES:
        if re.search(pattern, t, flags=re.IGNORECASE | re.DOTALL):
            flags.append({"name": name, "why": why, "weight": weight})
            score += weight

    for name, pattern, weight in SAFE_RULES:
        if re.search(pattern, t, flags=re.IGNORECASE):
            safe.append(name)
            score -= weight

    score = max(0, min(100, score))
    return {"score": score, "level": level_for(score), "flags": flags, "safe_signals": safe}


def level_for(score: int) -> str:
    if score < 25:
        return "Low"
    if score < 55:
        return "Medium"
    return "High"
