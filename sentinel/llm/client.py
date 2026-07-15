"""Thin LLM wrapper shared by every reasoning agent (CWE mapping, IDOR agent).

Only does two things: plain chat completion, and completion constrained to a
JSON schema (via tool-forcing on Anthropic, response_format on OpenAI/
OpenRouter). Agents should never talk to the anthropic/openai SDKs directly —
go through here so model choice and retry behavior stay in one place.

Three backends, checked in this order: anthropic (native SDK) > openrouter
(OpenAI SDK pointed at OpenRouter's base_url — OpenRouter is OpenAI-API-
compatible) > openai (native SDK, official API). "openrouter" and "openai"
share the same request shape below since OpenRouter mirrors OpenAI's API.
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
            "SENTINEL_OPENROUTER_API_KEY, or SENTINEL_OPENAI_API_KEY."
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    def complete(self, *, system: str, user: str, max_tokens: int = 2048) -> str:
        if self._backend == "anthropic":
            response = self._client.messages.create(
                model=settings.llm_model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
            return "".join(block.text for block in response.content if block.type == "text")
        response = self._client.chat.completions.create(
            model=settings.llm_model,
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
                model=settings.llm_model,
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

        response = self._client.chat.completions.create(
            model=settings.llm_model,
            max_tokens=max_tokens,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            response_format={"type": "json_object"},
        )
        return json.loads(response.choices[0].message.content or "{}")


_singleton: LlmClient | None = None


def get_llm_client() -> LlmClient:
    global _singleton
    if _singleton is None:
        _singleton = LlmClient()
    return _singleton
