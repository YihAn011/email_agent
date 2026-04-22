from __future__ import annotations

import os

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_ollama import ChatOllama

DEFAULT_OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
DEFAULT_PUTER_BASE_URL = os.getenv(
    "PUTER_BASE_URL",
    "https://api.puter.com/puterai/openai/v1/",
)


def resolve_provider(explicit_provider: str | None = None) -> str:
    provider = (explicit_provider or os.getenv("LLM_PROVIDER") or "gemini").strip().lower()
    if provider not in {"ollama", "gemini", "puter-openai"}:
        raise ValueError(
            f"Unsupported provider '{provider}'. Expected 'ollama', 'gemini', or 'puter-openai'."
        )
    return provider


def resolve_default_model(provider: str) -> str:
    if provider == "ollama":
        return os.getenv("OLLAMA_MODEL", "qwen3:latest")
    if provider == "puter-openai":
        return os.getenv("PUTER_MODEL", "gpt-5.4")
    return os.getenv("GEMINI_MODEL", "gemini-2.5-flash")


def ensure_google_api_key() -> None:
    if os.getenv("GOOGLE_API_KEY"):
        return
    gemini_key = os.getenv("GEMINI_API_KEY")
    if gemini_key:
        os.environ["GOOGLE_API_KEY"] = gemini_key
        return
    raise RuntimeError(
        "Missing Google API credentials. Set GOOGLE_API_KEY or GEMINI_API_KEY before running with provider=gemini."
    )


def ensure_puter_auth_token() -> str:
    token = (os.getenv("PUTER_AUTH_TOKEN") or "").strip()
    if token:
        return token
    raise RuntimeError(
        "Missing Puter auth token. Set PUTER_AUTH_TOKEN before running with provider=puter-openai."
    )


def build_chat_model(
    *,
    provider: str | None = None,
    model_name: str | None = None,
    temperature: float = 0,
    ollama_base_url: str | None = None,
):
    resolved_provider = resolve_provider(provider)
    resolved_model = model_name or resolve_default_model(resolved_provider)

    if resolved_provider == "ollama":
        return ChatOllama(
            model=resolved_model,
            temperature=temperature,
            base_url=ollama_base_url or DEFAULT_OLLAMA_BASE_URL,
        )

    if resolved_provider == "puter-openai":
        try:
            from langchain_openai import ChatOpenAI
        except ImportError as exc:
            raise RuntimeError(
                "Missing langchain-openai. Install it before running with provider=puter-openai."
            ) from exc
        return ChatOpenAI(
            model=resolved_model,
            temperature=temperature,
            api_key=ensure_puter_auth_token(),
            base_url=DEFAULT_PUTER_BASE_URL,
        )

    ensure_google_api_key()
    return ChatGoogleGenerativeAI(model=resolved_model, temperature=temperature)
