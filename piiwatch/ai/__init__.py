"""AI-assisted contextual classification for PIIWatch.

Provider-agnostic: see piiwatch.ai.provider for the LLMProvider interface,
piiwatch.ai.classifier for the AIClassifier that uses it, and
piiwatch.ai.factory for constructing a provider from simple config.
"""

from piiwatch.ai.classifier import AIClassifier
from piiwatch.ai.factory import build_provider
from piiwatch.ai.provider import LLMError, LLMProvider, LLMRequest

__all__ = ["AIClassifier", "build_provider", "LLMError", "LLMProvider", "LLMRequest"]
