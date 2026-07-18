"""Thin LLM wrapper shared by every reasoning agent (CWE mapping, IDOR agent).

Only does two things: plain chat completion, and completion constrained to a
JSON schema (via tool-forcing on Anthropic, response_format on OpenAI/
OpenRouter). Agents should never talk to the anthropic/openai SDKs directly —
go through here so model choice and retry behavior stay in one place.

Four backends, checked in this order: anthropic (native SDK) > tokenrouter
(OpenAI SDK pointed at TokenRouter's base_url) > openrouter (OpenAI SDK
pointed at OpenRouter's base_url) > openai (native SDK, official API).
TokenRouter, OpenRouter, and OpenAI share the same request shape below.
"""
from __future__ import annotations

import json
from typing import Any

from tenacity import retry, stop_after_attempt, wait_exponential

from sentinel.config import settings


class LlmConfigurationError(RuntimeError):
    pass


class LlmClient:
    def __init__(self) -> None:
        self._backend, self._client = self._build_backend()

    def _build_backend(self) -> tuple[str, Any]:
        if settings.anthropic_api_key:
            import anthropic

            return "anthropic", anthropic.Anthropic(api_key=settings.anthropic_api_key)
        if settings.tokenrouter_api_key:
            import openai

            return "tokenrouter", openai.OpenAI(
                api_key=settings.tokenrouter_api_key, base_url=settings.tokenrouter_base_url
            )
        if settings.openrouter_api_key:
            import openai

            return "openai", openai.OpenAI(
                api_key=settings.openrouter_api_key, base_url=settings.openrouter_base_url
            )
        if settings.openai_api_key:
            import openai

            return "openai", openai.OpenAI(api_key=settings.openai_api_key)
        raise LlmConfigurationError(
            "No LLM API key configured. Set SENTINEL_ANTHROPIC_API_KEY, "
            "SENTINEL_TOKENROUTER_API_KEY, SENTINEL_OPENROUTER_API_KEY, or "
            "SENTINEL_OPENAI_API_KEY."
        )

    @property
    def model_name(self) -> str:
        """Return the configured model identifier for the selected backend."""

        if self._backend == "tokenrouter":
            return settings.tokenrouter_model
        return settings.llm_model

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    def complete(self, *, system: str, user: str, max_tokens: int = 2048) -> str:
        if self._backend == "anthropic":
            response = self._client.messages.create(
                model=self.model_name,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
            return "".join(block.text for block in response.content if block.type == "text")
        response = self._client.chat.completions.create(
            model=self.model_name,
            max_tokens=max_tokens,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        )
        return response.choices[0].message.content or ""

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    def complete_json(
        self, *, system: str, user: str, json_schema: dict[str, Any], schema_name: str, max_tokens: int = 4096
    ) -> dict[str, Any]:
        """Force the model to return an object matching json_schema."""
        if self._backend == "anthropic":
            tool = {
                "name": schema_name,
                "description": f"Return the {schema_name} result.",
                "input_schema": json_schema,
            }
            response = self._client.messages.create(
                model=self.model_name,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
                tools=[tool],
                tool_choice={"type": "tool", "name": schema_name},
            )
            for block in response.content:
                if block.type == "tool_use":
                    return block.input
            raise LlmConfigurationError("Model did not return a tool_use block")

        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        if self._backend == "tokenrouter":
            # The selected GLM route may not implement OpenAI's optional
            # response_format JSON mode.  Ask for raw JSON instead, validate
            # it locally, and fall back safely in the caller if it is invalid.
            messages[0]["content"] += (
                " Return only one valid JSON object that follows this schema: "
                f"{json.dumps(json_schema, separators=(',', ':'))}. "
                "Do not use Markdown fences or add commentary."
            )
            response = self._client.chat.completions.create(
                model=self.model_name,
                max_tokens=max_tokens,
                messages=messages,
            )
        else:
            response = self._client.chat.completions.create(
                model=self.model_name,
                max_tokens=max_tokens,
                messages=messages,
                response_format={"type": "json_object"},
            )
        content = (response.choices[0].message.content or "").strip()
        if content.startswith("```") and content.endswith("```"):
            content = content.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
        parsed = json.loads(content or "{}")
        if not isinstance(parsed, dict):
            raise LlmConfigurationError("Model did not return a JSON object")
        return parsed


_singleton: LlmClient | None = None


def get_llm_client() -> LlmClient:
    global _singleton
    if _singleton is None:
        _singleton = LlmClient()
    return _singleton
