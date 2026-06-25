"""Factory for constructing an LLMProvider from simple config.

Keeps provider selection (CLI flag, env var, etc.) decoupled from the
provider classes themselves.
"""

from __future__ import annotations

import os

from piiwatch.ai.provider import LLMError, LLMProvider

_SUPPORTED = ("anthropic", "openai")


def build_provider(name: str | None = None, *, api_key: str | None = None, model: str | None = None) -> LLMProvider:
    """Construct a provider by name. If name is None, checks the
    PIIWATCH_AI_PROVIDER environment variable, defaulting to "anthropic".

    Raises LLMError if the provider name is unsupported or the
    corresponding SDK/credentials aren't available -- callers should
    catch this and either disable the AI layer or surface a clear error,
    never let an AI-layer misconfiguration crash an entire scan.
    """
    name = name or os.environ.get("PIIWATCH_AI_PROVIDER", "anthropic")
    name = name.lower()

    if name == "anthropic":
        from piiwatch.ai.anthropic_provider import AnthropicProvider, DEFAULT_MODEL

        return AnthropicProvider(api_key=api_key, model=model or DEFAULT_MODEL)
    if name == "openai":
        from piiwatch.ai.openai_provider import OpenAIProvider, DEFAULT_MODEL

        return OpenAIProvider(api_key=api_key, model=model or DEFAULT_MODEL)

    raise LLMError(f"unsupported AI provider '{name}'. Supported providers: {', '.join(_SUPPORTED)}")
