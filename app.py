"""Scam Shield: private, on-device scam detector. Run with: streamlit run app.py"""
import re
import streamlit as st
from explain import MODEL, explain, warmup
from rules import analyze

SAMPLES = {
    "Fake KYC (bank)": (
        "Dear customer, your SBI account will be blocked today. "
        "Update your KYC immediately: http://sbi-kyc-update.xyz/login"
    ),
    "Lottery prize": (
        "Congratulations! You have won Rs 25,00,000 in the Lucky Draw. "
        "Pay Rs 4,999 processing fee to claim your prize."
    ),
    "Courier fee": (
        "Your parcel is held at customs. Pay a Rs 49 delivery fee here to release it: "
        "bit.ly/3xYzParcel"
    ),
    "Fake Job / Telegram": (
        "Hi, this is Anita from HR. We reviewed your profile and would like to move forward. "
        "Please contact our manager on Telegram @hrmanager_official."
    ),
    "Genuine OTP (safe)": "123456 is your OTP for login to Amazon. Do not share it with anyone.",
    "Genuine bank alert (safe)": (
        "Rs 500.00 debited from A/c XX1234 on 31-Oct to UPI/ramesh@okaxis. "
        "If not you, call 1800-XXX-XXXX."
    ),
}

VERDICT_CARDS = {
    "HIGH RISK": {
        "headline": "🛑 DO NOT REPLY, CLICK, OR PAY",
        "subline": "This message exhibits strong scam patterns. Disregard and verify independently.",
        "bg_color": "#D32F2F",
        "text_color": "#FFFFFF",
    },
    "SUSPICIOUS": {
        "headline": "⚠️ PAUSE — VERIFY BEFORE ACTING",
        "subline": "Warning signals detected. Do not click links or share any private information.",
        "bg_color": "#F57C00",
        "text_color": "#FFFFFF",
    },
    "LOOKS SAFE": {
        "headline": "✅ LOOKS SAFE — NO COMMON SCAM SIGNS",
        "subline": "No recognized scam patterns found. Standard caution still applies.",
        "bg_color": "#2E7D32",
        "text_color": "#FFFFFF",
    },
}

st.set_page_config(
    page_title="Scam Shield — On-Device Scam Detector",
    page_icon="🛡️",
    layout="centered",
)


@st.cache_resource
def load_model():
    return warmup()


model_ready = load_model()

with st.sidebar:
    st.header("🛡️ Scam Shield")
    st.caption("Your device's private scam bodyguard")
    st.markdown("🔒 **100% On-Device**\nNothing leaves this computer.")

    if model_ready:
        st.success(f"Local model ready: `{MODEL}`")
    else:
        st.warning("Local model offline. Using fast built-in fallbacks.")

    st.markdown("---")
    choice = st.selectbox(
        "Try sample message:",
        ["(write your own)"] + list(SAMPLES.keys()),
        index=0,
    )

st.title("🛡️ Scam Shield")
st.markdown(
    "**Private, on-device scam detection.** "
    "Check suspicious SMS, WhatsApp, or email messages instantly without uploading private data to the cloud."
)

text = st.text_area(
    "Paste message to check:",
    value=SAMPLES.get(choice, ""),
    height=140,
    key=f"msg::{choice}",
    placeholder="Paste a suspicious SMS, WhatsApp message or email here...",
)

check_clicked = st.button("Check Message", type="primary", use_container_width=True)

if (check_clicked or choice != "(write your own)") and text.strip():
    result = analyze(text)
    level = result["level"]
    score = result["score"]
    card = VERDICT_CARDS[level]

    st.markdown("---")

    # Big 1-glance verdict banner for hurried users
    st.markdown(
        f"""
        <div style="background-color: {card['bg_color']}; color: {card['text_color']}; 
                    padding: 20px 24px; border-radius: 12px; margin-bottom: 20px; text-align: center;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.15);">
            <div style="font-size: 26px; font-weight: 800; letter-spacing: -0.5px;">{card['headline']}</div>
            <div style="font-size: 15px; margin-top: 6px; opacity: 0.95;">{card['subline']}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Risk Score & Progress
    col1, col2 = st.columns(2)
    col1.metric("Risk Score", f"{score} / 100")
    col2.metric("Verdict Level", level)
    st.progress(score / 100)

    # Message text with highlighted red flags
    st.subheader("Message Analysis")
    shown = text.replace("$", "\\$")
    for flag in sorted(result["flags"], key=lambda f: -len(f["match"])):
        shown = re.sub(
            re.escape(flag["match"]),
            lambda m: f":red[**{m.group(0)}**]",
            shown,
            flags=re.IGNORECASE,
        )
    st.markdown(f"> {shown.replace(chr(10), '  ' + chr(10))}")

    # Detected Red Flags list
    if result["flags"]:
        st.subheader("🚩 Detected Red Flags")
        for f in result["flags"]:
            st.markdown(f"- **{f['flag']}**: `{f['match']}`")
    else:
        st.info("No suspicious keywords, urgency traps, or secret requests detected.")

    # Plain language explanation from local LLM
    with st.spinner("Analyzing with local open-source model..."):
        info = explain(text, result)

    st.subheader("💡 Why this verdict?")
    st.write(info["explanation"])

    st.subheader("✅ Recommended Next Steps")
    for step in info["what_to_do"]:
        st.markdown(f"- {step}")

    st.subheader("👨‍👩‍👧‍👦 Warn My Family (One-Tap Copy)")
    st.caption("Send this pre-drafted message to family or group chats:")
    st.code(info["family_message"], language=None, wrap_lines=True)

    who = f"{MODEL} via Ollama" if info.get("source") == "model" else "built-in safety rules"
    st.caption(f"Explanation generated locally by {who}. Scam Shield is an assistant, not a guarantee.")

