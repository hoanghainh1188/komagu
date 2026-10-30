"""Komagu Cognitive AI Engine (Tier 2 BYO-LLM Runtime).

Provides zero-dependency headless execution for multi-agent security audits
(Stack Detection, Route Mapping, BOLA Auditing, SQLi Auditing, and Skeptic Verification).
"""

from operate.ai.client import LLMClient
from operate.ai.runner import HeadlessAIRunner

__all__ = ["LLMClient", "HeadlessAIRunner"]
