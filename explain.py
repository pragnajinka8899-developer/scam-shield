"""Explanation layer: a local open-source model (via Ollama) writes the plain-language text."""
import json
import os
import ollama

# Exact model name from `ollama list`. Override without editing code:
# Windows (PowerShell): $env:SCAM_MODEL = "gemma3:1b"
# Mac / Linux: export SCAM_MODEL=gemma3:1b
MODEL = os.getenv("SCAM_MODEL", "gemma3:1b")

SYSTEM = (
    "You are a scam-awareness assistant for ordinary people. You receive a message and a list "
    "of red flags found by a rule engine. Use ONLY the message and the flags; never invent "
    "facts, links or phone numbers. Write simple language a grandparent could understand. "
    "Reply with JSON only, using exactly these keys: "
    '"explanation" (2-3 short sentences on why the message is risky, or why it looks safe), '
    '"what_to_do" (a list of exactly 3 short action steps), '
    '"family_message" (a short, friendly warning to forward to a family member; '
    "if the message looks safe, say that no action is needed)."
)


def warmup():
    """Load the model into memory once so the first real check is fast."""
    try:
        ollama.chat(
            model=MODEL,
            messages=[{"role": "user", "content": "hi"}],
            keep_alive="30m",
        )
        return True
    except Exception:
        return False


def _fallback(result):
    """Used when the model is slow, offline or returns bad JSON. The demo never crashes."""
    if result["flags"]:
        why = ", ".join(f["flag"].lower() for f in result["flags"])
        explanation = f"This message shows common scam signs: {why}."
    else:
        explanation = "No common scam patterns were found in this message."
    return {
        "explanation": explanation,
        "what_to_do": [
            "Do not click any links or numbers in the message.",
            "Never share OTPs, PINs, passwords, or personal details with anyone.",
            "Contact the organisation directly using its official app or website.",
        ],
        "family_message": (
            "Careful! I received a suspicious message that looks like a scam. "
            "Never share OTPs or click unknown links."
        ),
        "source": "fallback",
    }


def explain(text, result):
    prompt = (
        f"MESSAGE:\n{text}\n\n"
        f"VERDICT: {result['level']} ({result['score']}/100)\n"
        f"FLAGS: {json.dumps(result['flags'])}"
    )
    try:
        reply = ollama.chat(
            model=MODEL,
            format="json",
            messages=[
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": prompt},
            ],
            options={"temperature": 0.2, "num_predict": 220},
            keep_alive="30m",
        )
        data = json.loads(reply["message"]["content"])
        steps = data["what_to_do"]
        if isinstance(steps, str):
            steps = [steps]
        return {
            "explanation": str(data["explanation"]),
            "what_to_do": [str(s) for s in steps][:3],
            "family_message": str(data["family_message"]),
            "source": "model",
        }
    except Exception:
        return _fallback(result)

