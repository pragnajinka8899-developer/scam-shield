"""Rule engine: fast, explainable scam scoring. No model needed, so it never fails."""
import re

# (name, weight, regex). Patterns run on lowercase text.
RULES = [
    (
        "Urgency or threat",
        20,
        r"\b(urgent(ly)?|immediately|right now|last chance|final notice|blocked|suspended|"
        r"deactivated|disconnected|expires?|expired|within \d+ ?(hours?|hrs?|minutes?|mins?))\b",
    ),
    (
        "Asks for OTP / PIN / password",
        35,
        r"\b(shar(e|ing)|send(ing)?|tell|enter|provid(e|ing)|giv(e|ing)|submit|confirm|reply with)\b"
        r"[^.\n]{0,40}\b(otp|pin|cvv|password|passcode|aadhaar|aadhar)\b",
    ),
    (
        "Account-verification (KYC) bait",
        20,
        r"\b(kyc|verify your (account|identity|details)|update your (pan|aadhaar|aadhar|details)|"
        r"pan card (is )?(blocked|suspended)|unusual activity|suspicious activity)\b",
    ),
    (
        "Prize, lottery or free reward",
        25,
        r"\b(you (have )?won|congratulations|lottery|lucky draw|prize|reward points?|gift card|"
        r"cashback of)\b",
    ),
    (
        "Suspicious or shortened link",
        25,
        r"(bit\.ly|tinyurl\.com|cutt\.ly|is\.gd|goo\.gl|t\.co/|"
        r"\b(?:https?://\S*|\b)[\w.-]+\.(xyz|top|click|icu|live|info|site)\b|"
        r"https?://\d{1,3}(\.\d{1,3}){3})",
    ),
    (
        "Demands payment or money transfer",
        25,
        r"\b(pay|transfer|send|deposit)\b[^.\n]{0,40}\b(fee|fees|charges?|amount|deposit|rs\.?|inr|upi)\b",
    ),
    (
        "Refund / collect-request / QR trick",
        30,
        r"\b(refund|collect request|scan (this |the )?qr|accept (the |this )?request)\b",
    ),
    (
        "Fake investment or easy-money promise",
        25,
        r"\b(work from home|part[- ]time job|daily payout|task[- ]based|double your money|"
        r"guaranteed returns?|risk[- ]free|earn rs\.? ?\d[\d,]* ?(per|a|/) ?(day|hour|week))\b",
    ),
    (
        "Courier / customs pretext",
        15,
        r"\b(parcel|package|courier|customs|delivery)\b[^.\n]{0,60}"
        r"\b(held|stuck|pending|unpaid|incomplete|reschedule|release)\b",
    ),
    (
        "Fake authority threat",
        30,
        r"\b(cbi|narcotics|arrest warrant|digital arrest|cyber ?crime|income tax (department|dept))\b",
    ),
    (
        "Pretends to be family or a friend",
        20,
        r"\b(new number|lost my phone|changed my number|phone (is )?broken)\b",
    ),
    (
        "Moves you to Telegram / WhatsApp",
        15,
        r"\b(contact|message|join|chat)\b[^.\n]{0,40}\b(telegram|whatsapp)\b|t\.me/",
    ),
    (
        "Unsolicited recruiter outreach",
        15,
        r"\b(from hr|hr team|recruit(er|ment)|reviewed your profile)\b",
    ),
    (
        "Mentions a bank, government or brand",
        10,
        r"\b(sbi|hdfc|icici|axis bank|kotak|rbi|paytm|phonepe|income tax|fedex|dhl|india post|"
        r"electricity|netflix|amazon)\b",
    ),
]

# Standard safety warnings ("Do not share your OTP") are removed before scanning,
# so genuine bank and OTP messages are not flagged by mistake.
SAFE_WARNING = re.compile(
    r"\b(do not|don't|dont|never|not to)\s+(share|disclose|give|reveal)\b[^.\n]*", re.IGNORECASE
)

# Exception for legitimate OTP sharing (e.g., driver, rider, delivery partner/agent)
SAFE_OTP_EXCEPTION = re.compile(
    r"\b(shar(e|ing)?|tell|giv(e|ing)|provid(e|ing)|send)\b[^.\n]{0,50}\b(otp|pin|code)?\b[^.\n]{0,50}\b(driver|rider|delivery partner|delivery agent)\b|"
    r"\b(driver|rider|delivery partner|delivery agent)\b[^.\n]{0,50}\b(shar(e|ing)?|tell|giv(e|ing)|provid(e|ing)|send)\b[^.\n]{0,50}\b(otp|pin|code)\b",
    re.IGNORECASE,
)

HIGH, SUSPICIOUS = 50, 25


def analyze(text):
    """Return {"score": 0-100, "level": str, "flags": [{"flag", "match"}]}."""
    cleaned = SAFE_WARNING.sub("", text.lower())
    flags, score = [], 0
    for name, weight, pattern in RULES:
        if name == "Asks for OTP / PIN / password" and SAFE_OTP_EXCEPTION.search(cleaned):
            continue
        m = re.search(pattern, cleaned, re.IGNORECASE)
        if m:
            flags.append({"flag": name, "match": m.group(0)})
            score += weight
    score = min(score, 100)
    if score >= HIGH:
        level = "HIGH RISK"
    elif score >= SUSPICIOUS:
        level = "SUSPICIOUS"
    else:
        level = "LOOKS SAFE"
    return {"score": score, "level": level, "flags": flags}


if __name__ == "__main__":
    demo = "Your SBI account will be blocked today. Update your KYC immediately: http://sbi-kyc-update.xyz/login"
    print(analyze(demo))

