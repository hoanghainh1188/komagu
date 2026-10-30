"""Zero-dependency HTTP client for OpenAI-compatible LLM endpoints (Ollama, vLLM, etc.).

Adheres strictly to Komagu's zero 3rd-party dependency invariant (Python 3.8+ stdlib).
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional


class LLMClient:
    """Standard-library client for OpenAI-compatible /chat/completions endpoints."""

    def __init__(
        self,
        endpoint: str = "http://localhost:11434/v1",
        model: str = "llama3.1",
        api_key: Optional[str] = None,
        timeout: int = 120,
    ) -> None:
        raw_endpoint = endpoint.rstrip("/")
        if not raw_endpoint.endswith("/chat/completions"):
            self.endpoint = f"{raw_endpoint}/chat/completions"
        else:
            self.endpoint = raw_endpoint
        self.model = model
        self.api_key = api_key or "ollama"
        self.timeout = timeout

    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
    ) -> str:
        """Send a chat completion request and return the assistant response content."""
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens:
            payload["max_tokens"] = max_tokens

        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": "Komagu-Headless-AI/1.5.0",
        }

        req = urllib.request.Request(self.endpoint, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8")
                res_json = json.loads(body)
                choices = res_json.get("choices", [])
                if not choices:
                    raise RuntimeError(f"LLM API returned no choices: {body}")
                msg = choices[0].get("message", {})
                return msg.get("content", "")
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"LLM API HTTP {e.code} error: {err_body}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"Failed to connect to LLM endpoint at {self.endpoint}: {e.reason}") from e

    @staticmethod
    def extract_json(content: str) -> Any:
        """Extract and parse JSON from Markdown code blocks or raw text string."""
        content = content.strip()
        # Look for markdown code fence ```json ... ``` or ``` ... ```
        match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", content)
        if match:
            text = match.group(1).strip()
        else:
            text = content
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            # Fallback: search for first '{' or '[' to last '}' or ']'
            start_brace = text.find("{")
            start_bracket = text.find("[")
            if start_brace != -1 and (start_bracket == -1 or start_brace < start_bracket):
                end_brace = text.rfind("}")
                if end_brace != -1:
                    return json.loads(text[start_brace : end_brace + 1])
            elif start_bracket != -1:
                end_bracket = text.rfind("]")
                if end_bracket != -1:
                    return json.loads(text[start_bracket : end_bracket + 1])
            raise RuntimeError(f"Could not parse valid JSON from LLM response:\n{content}") from exc
