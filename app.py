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


@st.cache_resource
def load_whisper():
    try:
        from faster_whisper import WhisperModel
        return WhisperModel("base", device="cpu", compute_type="int8")
    except Exception:
        return None


def transcribe_audio(audio_source):
    """Transcribe audio from st.audio_input or st.file_uploader on-device."""
    model = load_whisper()
    if model is None:
        return None, "Whisper speech model could not be loaded on this device."
    try:
        if hasattr(audio_source, "seek"):
            audio_source.seek(0)
        segments, _ = model.transcribe(audio_source, vad_filter=True)
        text = " ".join(seg.text for seg in segments).strip()
        return text, None
    except Exception as e:
        return None, f"Transcription failed: {str(e)}"


def display_results(text):
    """Render verdict banner, metrics, flags, explanation, and family warning."""
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
    mode = st.radio("Mode", ["Check a message", "Voice check"], index=0)

    if mode == "Check a message":
        choice = st.selectbox(
            "Try sample message:",
            ["(write your own)"] + list(SAMPLES.keys()),
            index=0,
        )
    else:
        choice = "(write your own)"

if mode == "Check a message":
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
        display_results(text.strip())

elif mode == "Voice check":
    st.title("🎙️ Voice Check")
    st.markdown(
        "**Private, on-device voice scam detection.** "
        "Check suspicious phone calls or voice notes directly from your microphone or audio files."
    )
    st.caption("Voice is processed on this device. Nothing is uploaded.")

    tab_rec, tab_file = st.tabs(["🎤 Record Microphone", "📁 Upload Audio File"])
    audio_source = None

    with tab_rec:
        rec = st.audio_input("Record suspicious call or voice message:")
        if rec is not None:
            audio_source = rec

    with tab_file:
        uploaded = st.file_uploader(
            "Upload audio file:",
            type=["wav", "mp3", "m4a"],
            help="Supports WAV, MP3, or M4A audio formats",
        )
        if uploaded is not None and audio_source is None:
            audio_source = uploaded

    if audio_source is not None:
        source_id = getattr(audio_source, "file_id", None) or getattr(audio_source, "name", "rec")
        if st.session_state.get("transcribed_id") != source_id:
            with st.spinner("Transcribing on this device..."):
                transcript, err = transcribe_audio(audio_source)
                if err:
                    st.error(f"Error during transcription: {err}")
                    st.session_state["voice_text"] = ""
                else:
                    st.session_state["voice_text"] = transcript or ""
                st.session_state["transcribed_id"] = source_id

        current_transcript = st.session_state.get("voice_text", "")
        if current_transcript:
            st.subheader("Transcribed Message")
            st.caption("Review or edit the transcript below:")
            edited_text = st.text_area(
                "Transcript:",
                value=current_transcript,
                height=120,
                key="voice_transcript_area",
            )
            if st.button("Check Voice Message", type="primary", use_container_width=True) or not st.session_state.get("voice_checked_once"):
                st.session_state["voice_checked_once"] = True
                if edited_text.strip():
                    display_results(edited_text.strip())
                else:
                    st.warning("Please provide or edit the message text to check.")
        else:
            st.info("No speech detected in audio. Please speak clearly into the microphone or upload an audio recording.")
