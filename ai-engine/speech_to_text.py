"""
SentinelOS — Module 1: Speech → Text
Uses OpenAI Whisper (runs 100% locally, completely free).

Setup:
    pip install openai-whisper
    First run downloads the model (~140MB for 'base')

Whisper model sizes (all free, local):
    tiny   → fastest, less accurate  (~75MB)
    base   → good balance            (~140MB)  ← default
    small  → better accuracy         (~460MB)
    medium → best for Indian English (~1.5GB)
"""

import whisper
import base64
import tempfile
import os
import json

MODEL_SIZE = "base"  # change to "small" for better Hindi/Indian English

print(f"[SpeechToText] Loading Whisper model: {MODEL_SIZE} ...")
_model = whisper.load_model(MODEL_SIZE)
print(f"[SpeechToText] Model ready.")


def transcribe_audio_file(file_path: str) -> dict:
    """
    Transcribe audio from a local file path.
    Supports: mp3, mp4, wav, m4a, ogg, flac, webm

    Returns:
        {
            "transcript": "please share your otp immediately",
            "language": "en",
            "confidence": 0.91,
            "segments": [{"start": 0.0, "end": 1.2, "text": "..."}]
        }
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Audio file not found: {file_path}")

    result = _model.transcribe(file_path, fp16=False)

    segments = result.get("segments", [])
    avg_logprob = 0.0
    if segments:
        avg_logprob = sum(s.get("avg_logprob", 0) for s in segments) / len(segments)
    confidence = max(0.0, min(1.0, 1.0 + avg_logprob))

    return {
        "transcript": result["text"].strip(),
        "language": result.get("language", "en"),
        "confidence": round(confidence, 2),
        "segments": [
            {"start": s["start"], "end": s["end"], "text": s["text"].strip()}
            for s in segments
        ]
    }


def transcribe_audio(audio_base64: str, language: str = "en") -> dict:
    """
    Transcribe audio from base64-encoded bytes.
    Kotlin records audio → encodes as base64 → sends over HTTP → we decode here.

    Args:
        audio_base64: base64 string of audio bytes (wav/m4a/ogg)
        language: hint for Whisper ("en", "hi", "te", "ta", "mr" etc.)
    """
    audio_bytes = base64.b64decode(audio_base64)

    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
        tmp.write(audio_bytes)
        tmp_path = tmp.name

    try:
        result = _model.transcribe(tmp_path, fp16=False, language=language)

        segments = result.get("segments", [])
        avg_logprob = 0.0
        if segments:
            avg_logprob = sum(s.get("avg_logprob", 0) for s in segments) / len(segments)
        confidence = max(0.0, min(1.0, 1.0 + avg_logprob))

        return {
            "transcript": result["text"].strip(),
            "language": result.get("language", language),
            "confidence": round(confidence, 2),
            "segments": [
                {"start": s["start"], "end": s["end"], "text": s["text"].strip()}
                for s in segments
            ]
        }
    finally:
        os.unlink(tmp_path)


if __name__ == "__main__":
    test_file = "test.wav"
    if os.path.exists(test_file):
        result = transcribe_audio_file(test_file)
        print(json.dumps(result, indent=2))
    else:
        print("Drop an audio file as test.wav in this folder to test.")