"""Zero-dependency HTTP client for OpenAI-compatible LLM endpoints (Ollama, vLLM, etc.).

Adheres strictly to Komagu's zero 3rd-party dependency invariant (Python 3.8+ stdlib).
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

# OpenAI-compatible `reasoning_effort` values; Ollama's /v1 also accepts "none" to turn thinking off (#382)
REASONING_EFFORTS = ("none", "low", "medium", "high")


class LLMClient:
    """Standard-library client for OpenAI-compatible /chat/completions endpoints."""

    def __init__(
        self,
        endpoint: str = "http://localhost:11434/v1",
        model: str = "llama3.1",
        api_key: Optional[str] = None,
        timeout: int = 120,
        reasoning_effort: Optional[str] = None,
    ) -> None:
        if reasoning_effort is not None and reasoning_effort not in REASONING_EFFORTS:
            raise ValueError(f"reasoning_effort must be one of {', '.join(REASONING_EFFORTS)}")
        if urllib.parse.urlparse(endpoint).scheme.lower() not in ("http", "https"):
            raise ValueError("LLM endpoint must be an http:// or https:// URL")
        raw_endpoint = endpoint.rstrip("/")
        if not raw_endpoint.endswith("/chat/completions"):
            self.endpoint = f"{raw_endpoint}/chat/completions"
        else:
            self.endpoint = raw_endpoint
        self.model = model
        self.api_key = api_key or "ollama"
        self.timeout = timeout
        self.reasoning_effort = reasoning_effort
        # Running totals across chat() calls, read by the runner for ai-run-stats.json
        self.usage: Dict[str, float] = {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0, "seconds": 0.0}

    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
    ) -> str:
        """Send a chat completion request and return the assistant response content."""
        data = json.dumps(self.build_payload(messages, temperature, max_tokens)).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": "Komagu-Headless-AI/1.5.0",
        }

        req = urllib.request.Request(self.endpoint, data=data, headers=headers, method="POST")
        started = time.monotonic()
        try:
            # The endpoint scheme is checked to be http(s) in __init__.
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # nosec B310
                body = resp.read().decode("utf-8")
                res_json = json.loads(body)
                self._record_usage(res_json.get("usage") or {}, time.monotonic() - started)
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

    def build_payload(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Request body for /chat/completions; `reasoning_effort` is sent only when it was set."""
        payload: Dict[str, Any] = {"model": self.model, "messages": messages, "temperature": temperature}
        if max_tokens:
            payload["max_tokens"] = max_tokens
        if self.reasoning_effort:
            payload["reasoning_effort"] = self.reasoning_effort
        return payload

    def _record_usage(self, usage: Dict[str, Any], seconds: float) -> None:
        self.usage = {
            "calls": self.usage["calls"] + 1,
            "prompt_tokens": self.usage["prompt_tokens"] + int(usage.get("prompt_tokens") or 0),
            "completion_tokens": self.usage["completion_tokens"] + int(usage.get("completion_tokens") or 0),
            "seconds": round(self.usage["seconds"] + seconds, 3),
        }

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


def _next_char(text: str, i: int) -> Tuple[str, int]:
    """First non-space character at or after i, and its index ("" at the end)."""
    while i < len(text) and text[i].isspace():
        i += 1
    return (text[i], i) if i < len(text) else ("", i)


def _closes_string(text: str, i: int, container: str, is_key: bool) -> bool:
    """Whether the quote at text[i] can close the current string, judged by what follows it."""
    ch, j = _next_char(text, i + 1)
    if is_key:
        return ch == ":"
    if container == "{":
        return ch == "}" or (ch == "," and _next_char(text, j + 1)[0] == '"')
    if container == "[":
        return ch in ",]"
    return ch == ""


def repair_json_quotes(content: str) -> str:
    """Escape `"` characters that cannot close the string they appear in (#323).

    Small models copy code into string values without escaping it, for example
    `"code_before": "SELECT * FROM orders WHERE id = " + id",`. A quote inside a string is kept as
    the closing quote only when what follows fits the enclosing object or array: `:` after a key;
    `}` or `, "` in an object; `,` or `]` in an array.
    Only the JSON part of the reply (fenced block, or first `{` to last `}`) is repaired and returned.
    """
    text = content.strip()
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    if match:
        text = match.group(1).strip()
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        text = text[start : end + 1]

    out: List[str] = []
    stack: List[str] = []
    in_string = escaped = is_key = expecting_key = False
    for i, ch in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                if _closes_string(text, i, stack[-1] if stack else "", is_key):
                    in_string = False
                else:
                    out.append('\\"')
                    continue
        elif ch == '"':
            in_string, is_key = True, bool(stack) and stack[-1] == "{" and expecting_key
        elif ch in "{[":
            stack.append(ch)
            expecting_key = ch == "{"
        elif ch in "}]":
            if stack:
                stack.pop()
            expecting_key = False
        elif ch == ",":
            expecting_key = bool(stack) and stack[-1] == "{"
        elif ch == ":":
            expecting_key = False
        out.append(ch)
    return "".join(out)
