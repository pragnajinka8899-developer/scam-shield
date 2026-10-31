"""Scam Shield: private, on-device scam detector. Run with: streamlit run app.py"""
import hashlib
import io
import re
import wave
import numpy as np
import cv2
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


def is_audio_too_short(audio_bytes, min_duration=0.5):
    """Check if audio is empty or under about min_duration seconds."""
    if not audio_bytes or len(audio_bytes) == 0:
        return True
    try:
        with wave.open(io.BytesIO(audio_bytes), "rb") as wf:
            frames = wf.getnframes()
            rate = wf.getframerate()
            if rate > 0:
                return (frames / float(rate)) < min_duration
    except Exception:
        pass
    try:
        import av
        with av.open(io.BytesIO(audio_bytes)) as container:
            if container.duration is not None:
                duration = float(container.duration / av.time.AV_TIME_BASE)
                return duration < min_duration
            if container.streams.audio:
                stream = container.streams.audio[0]
                if stream.duration is not None and stream.time_base is not None:
                    duration = float(stream.duration * stream.time_base)
                    return duration < min_duration
    except Exception:
        pass
    return len(audio_bytes) < 4000


def transcribe_audio(audio_bytes):
    """Transcribe audio from fresh bytes wrapped in a new io.BytesIO on-device."""
    model = load_whisper()
    if model is None:
        return None, "Whisper speech model could not be loaded on this device."
    try:
        fresh_stream = io.BytesIO(audio_bytes)
        segments, _ = model.transcribe(fresh_stream, vad_filter=True)
        text = " ".join(seg.text for seg in segments).strip()
        return text, None
    except Exception as e:
        return None, f"Transcription failed: {str(e)}"


def decode_qr(image_bytes):
    """Decode a QR code from raw image bytes using OpenCV. Returns decoded text or None."""
    try:
        if not image_bytes:
            return None
        arr = np.frombuffer(image_bytes, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            return None
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        variants = [img]
        for scale in (1.0, 2.0, 0.5, 3.0):
            g = gray if scale == 1.0 else cv2.resize(
                gray, None, fx=scale, fy=scale,
                interpolation=cv2.INTER_CUBIC if scale > 1 else cv2.INTER_AREA)
            variants.append(g)
            variants.append(cv2.copyMakeBorder(g, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255))
            variants.append(cv2.adaptiveThreshold(
                g, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 10))
            variants.append(cv2.GaussianBlur(g, (3, 3), 0))

        detectors = []
        if hasattr(cv2, "QRCodeDetectorAruco"):  # much better on photos of screens
            detectors.append(cv2.QRCodeDetectorAruco())
        detectors.append(cv2.QRCodeDetector())

        for detector in detectors:
            for v in variants:
                try:
                    data, _, _ = detector.detectAndDecode(v)
                except cv2.error:
                    continue
                if data:
                    return data
        return None
    except Exception:
        return None


def display_results(text, extra_flags=None, skip_llm=False):
    """Render verdict banner, metrics, flags, explanation, and family warning.

    Args:
        text: The message text to analyze.
        extra_flags: Optional list of {"flag", "match"} dicts to append after rule analysis.
        skip_llm: If True, use built-in fallback instead of the local LLM (for instant modes).
    """
    result = analyze(text)
    if extra_flags:
        for ef in extra_flags:
            result["flags"].append(ef)
            result["score"] = min(result["score"] + ef.get("weight", 0), 100)
        # Re-evaluate level after extra flags
        if result["score"] >= 50:
            result["level"] = "HIGH RISK"
        elif result["score"] >= 25:
            result["level"] = "SUSPICIOUS"
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

    if skip_llm:
        # Use built-in fallback for instant offline modes (e.g., QR scan)
        from explain import _fallback
        info = _fallback(result)
    else:
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
    mode = st.radio("Mode", ["Check a message", "Scan a QR code", "Voice check"], index=0)

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

elif mode == "Scan a QR code":
    st.title("📷 Scan a QR Code")
    st.markdown(
        "**Private, on-device QR scanner.** "
        "Check suspicious QR codes from screenshots or your camera. Instant, no model needed."
    )
    st.caption("Images are processed on this device. Nothing is uploaded.")

    tab_upload, tab_camera = st.tabs(["🖼️ Upload Image", "📸 Camera"])
    image_bytes = None

    with tab_upload:
        qr_file = st.file_uploader(
            "Upload a QR code image:",
            type=["png", "jpg", "jpeg"],
            help="Supports PNG and JPEG images",
        )
        if qr_file is not None:
            image_bytes = qr_file.getvalue()

    with tab_camera:
        cam = st.camera_input("Take a photo of the QR code:")
        if cam is not None and image_bytes is None:
            image_bytes = cam.getvalue()

    if image_bytes is not None:
        st.image(image_bytes, caption="Uploaded image", use_container_width=True)
        decoded = decode_qr(image_bytes)
        if decoded is None:
            st.warning("No QR code found in this image. Please upload a clear photo of a QR code.")
        else:
            st.subheader("QR Code Content")
            st.code(decoded, language=None, wrap_lines=True)

            # Check for UPI payment QR (extra flag)
            extra_flags = []
            if decoded.strip().lower().startswith("upi://pay"):
                extra_flags.append({
                    "flag": "UPI payment QR",
                    "match": "A QR code is only for paying. Never scan one to RECEIVE money.",
                    "weight": 30,
                })

            display_results(decoded, extra_flags=extra_flags, skip_llm=True)

elif mode == "Voice check":
    st.title("🎙️ Voice Check")
    st.markdown(
        "**Private, on-device voice scam detection.** "
        "Check suspicious phone calls or voice notes directly from your microphone or audio files."
    )
    st.caption("Voice is processed on this device. Nothing is uploaded.")

    if "recorder_key_counter" not in st.session_state:
        st.session_state["recorder_key_counter"] = 0

    recorder_key = f"voice_recorder_{st.session_state['recorder_key_counter']}"

    tab_rec, tab_file = st.tabs(["🎤 Record Microphone", "📁 Upload Audio File"])
    audio_bytes = None
    source_type = None

    with tab_rec:
        rec = st.audio_input("Record suspicious call or voice message:", key=recorder_key)
        if st.button("🔄 Record again"):
            st.session_state["recorder_key_counter"] += 1
            st.session_state.pop("voice_transcript", None)
            st.session_state.pop("voice_audio_hash", None)
            st.session_state.pop("last_source_type", None)
            st.session_state.pop("voice_checked_once", None)
            st.rerun()

    with tab_file:
        uploaded = st.file_uploader(
            "Upload audio file:",
            type=["wav", "mp3", "m4a"],
            help="Supports WAV, MP3, or M4A audio formats",
        )

    rec_bytes = rec.getvalue() if rec is not None else None
    up_bytes = uploaded.getvalue() if uploaded is not None else None

    # Handle source selection cleanly
    if rec_bytes and up_bytes:
        rec_hash = hashlib.md5(rec_bytes).hexdigest()
        up_hash = hashlib.md5(up_bytes).hexdigest()
        current_hash = st.session_state.get("voice_audio_hash")
        if up_hash != current_hash and rec_hash == current_hash:
            audio_bytes = up_bytes
            source_type = "upload"
        elif rec_hash != current_hash and up_hash == current_hash:
            audio_bytes = rec_bytes
            source_type = "rec"
        else:
            if st.session_state.get("last_source_type") == "upload":
                audio_bytes = up_bytes
                source_type = "upload"
            else:
                audio_bytes = rec_bytes
                source_type = "rec"
    elif rec_bytes:
        audio_bytes = rec_bytes
        source_type = "rec"
    elif up_bytes:
        audio_bytes = up_bytes
        source_type = "upload"

    if audio_bytes is not None:
        if is_audio_too_short(audio_bytes):
            st.warning("No audio captured, please record again")
        else:
            audio_hash = hashlib.md5(audio_bytes).hexdigest()
            if st.session_state.get("voice_audio_hash") != audio_hash:
                with st.spinner("Transcribing on this device..."):
                    transcript, err = transcribe_audio(audio_bytes)
                    if err:
                        st.error(f"Error during transcription: {err}")
                        st.session_state["voice_transcript"] = ""
                    else:
                        st.session_state["voice_transcript"] = transcript or ""
                    st.session_state["voice_audio_hash"] = audio_hash
                    st.session_state["last_source_type"] = source_type
                    st.session_state["voice_checked_once"] = False

            current_transcript = st.session_state.get("voice_transcript", "")
            if current_transcript:
                st.subheader("Transcribed Message")
                st.caption("Review or edit the transcript below:")
                edited_text = st.text_area(
                    "Transcript:",
                    value=current_transcript,
                    height=120,
                    key=f"voice_transcript_area_{audio_hash[:8]}",
                )
                if st.button("Check Voice Message", type="primary", use_container_width=True) or not st.session_state.get("voice_checked_once"):
                    st.session_state["voice_checked_once"] = True
                    if edited_text.strip():
                        display_results(edited_text.strip())
                    else:
                        st.warning("Please provide or edit the message text to check.")
            else:
                st.info("No speech detected in audio. Please speak clearly into the microphone or upload an audio recording.")
