from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import tenacity

from sentinel.llm import client as llm_client
from sentinel.llm.client import LlmClient, LlmConfigurationError


@pytest.fixture(autouse=True)
def _reset_singleton():
    llm_client._singleton = None
    yield
    llm_client._singleton = None


def _clear_keys(monkeypatch):
    monkeypatch.setattr(llm_client.settings, "anthropic_api_key", None)
    monkeypatch.setattr(llm_client.settings, "tokenrouter_api_key", None)
    monkeypatch.setattr(llm_client.settings, "openrouter_api_key", None)
    monkeypatch.setattr(llm_client.settings, "openai_api_key", None)


class TestBackendSelection:
    def test_no_key_raises_configuration_error(self, monkeypatch):
        _clear_keys(monkeypatch)
        with pytest.raises(LlmConfigurationError):
            LlmClient()

    def test_anthropic_key_selects_anthropic_backend(self, monkeypatch):
        _clear_keys(monkeypatch)
        monkeypatch.setattr(llm_client.settings, "anthropic_api_key", "ant-key")
        with patch("anthropic.Anthropic") as mock_anthropic:
            mock_anthropic.return_value = MagicMock()
            client = LlmClient()
        assert client._backend == "anthropic"
        mock_anthropic.assert_called_once_with(api_key="ant-key")

    def test_openrouter_key_selects_openai_sdk_with_openrouter_base_url(self, monkeypatch):
        _clear_keys(monkeypatch)
        monkeypatch.setattr(llm_client.settings, "openrouter_api_key", "or-key")
        monkeypatch.setattr(llm_client.settings, "openrouter_base_url", "https://openrouter.ai/api/v1")
        with patch("openai.OpenAI") as mock_openai:
            mock_openai.return_value = MagicMock()
            client = LlmClient()
        assert client._backend == "openai"
        mock_openai.assert_called_once_with(api_key="or-key", base_url="https://openrouter.ai/api/v1")

    def test_tokenrouter_key_selects_openai_sdk_with_tokenrouter_base_url(self, monkeypatch):
        _clear_keys(monkeypatch)
        monkeypatch.setattr(llm_client.settings, "tokenrouter_api_key", "tr-demo-key")
        monkeypatch.setattr(llm_client.settings, "tokenrouter_base_url", "https://api.tokenrouter.com/v1")
        monkeypatch.setattr(llm_client.settings, "tokenrouter_model", "openai:gpt-4o")
        with patch("openai.OpenAI") as mock_openai:
            mock_openai.return_value = MagicMock()
            client = LlmClient()
        assert client._backend == "tokenrouter"
        assert client.model_name == "openai:gpt-4o"
        mock_openai.assert_called_once_with(api_key="tr-demo-key", base_url="https://api.tokenrouter.com/v1")

    def test_openai_key_selects_native_openai_backend(self, monkeypatch):
        _clear_keys(monkeypatch)
        monkeypatch.setattr(llm_client.settings, "openai_api_key", "oai-key")
        with patch("openai.OpenAI") as mock_openai:
            mock_openai.return_value = MagicMock()
            client = LlmClient()
        assert client._backend == "openai"
        mock_openai.assert_called_once_with(api_key="oai-key")

    def test_anthropic_takes_precedence_when_multiple_keys_set(self, monkeypatch):
        monkeypatch.setattr(llm_client.settings, "anthropic_api_key", "ant-key")
        monkeypatch.setattr(llm_client.settings, "openrouter_api_key", "or-key")
        monkeypatch.setattr(llm_client.settings, "openai_api_key", "oai-key")
        with patch("anthropic.Anthropic") as mock_anthropic, patch("openai.OpenAI") as mock_openai:
            mock_anthropic.return_value = MagicMock()
            client = LlmClient()
        assert client._backend == "anthropic"
        mock_openai.assert_not_called()

    def test_openrouter_takes_precedence_over_openai_when_both_set(self, monkeypatch):
        _clear_keys(monkeypatch)
        monkeypatch.setattr(llm_client.settings, "openrouter_api_key", "or-key")
        monkeypatch.setattr(llm_client.settings, "openai_api_key", "oai-key")
        with patch("openai.OpenAI") as mock_openai:
            mock_openai.return_value = MagicMock()
            LlmClient()
        mock_openai.assert_called_once_with(api_key="or-key", base_url=llm_client.settings.openrouter_base_url)

    def test_tokenrouter_takes_precedence_over_openrouter_and_openai(self, monkeypatch):
        _clear_keys(monkeypatch)
        monkeypatch.setattr(llm_client.settings, "tokenrouter_api_key", "tr-demo-key")
        monkeypatch.setattr(llm_client.settings, "openrouter_api_key", "or-key")
        monkeypatch.setattr(llm_client.settings, "openai_api_key", "oai-key")
        with patch("openai.OpenAI") as mock_openai:
            mock_openai.return_value = MagicMock()
            client = LlmClient()
        assert client._backend == "tokenrouter"
        mock_openai.assert_called_once_with(
            api_key="tr-demo-key", base_url=llm_client.settings.tokenrouter_base_url
        )


class TestCompleteAnthropic:
    def test_complete_returns_joined_text_blocks(self, monkeypatch):
        _clear_keys(monkeypatch)
        monkeypatch.setattr(llm_client.settings, "anthropic_api_key", "ant-key")
        with patch("anthropic.Anthropic") as mock_anthropic:
            fake_client = MagicMock()
            text_block = MagicMock(type="text", text="hello")
            fake_client.messages.create.return_value = MagicMock(content=[text_block])
            mock_anthropic.return_value = fake_client
            client = LlmClient()
            result = client.complete(system="sys", user="usr")
        assert result == "hello"

    def test_complete_json_returns_tool_use_input(self, monkeypatch):
        _clear_keys(monkeypatch)
        monkeypatch.setattr(llm_client.settings, "anthropic_api_key", "ant-key")
        with patch("anthropic.Anthropic") as mock_anthropic:
            fake_client = MagicMock()
            tool_block = MagicMock(type="tool_use", input={"applicable": True})
            fake_client.messages.create.return_value = MagicMock(content=[tool_block])
            mock_anthropic.return_value = fake_client
            client = LlmClient()
            result = client.complete_json(
                system="sys", user="usr", json_schema={"type": "object"}, schema_name="verdict"
            )
        assert result == {"applicable": True}

    def test_complete_json_raises_when_no_tool_use_block_returned(self, monkeypatch):
        _clear_keys(monkeypatch)
        monkeypatch.setattr(llm_client.settings, "anthropic_api_key", "ant-key")
        with patch("anthropic.Anthropic") as mock_anthropic:
            fake_client = MagicMock()
            text_block = MagicMock(type="text", text="no tool call")
            fake_client.messages.create.return_value = MagicMock(content=[text_block])
            mock_anthropic.return_value = fake_client
            client = LlmClient()
            # complete_json retries any exception 3x (tenacity) before giving
            # up, wrapping the original LlmConfigurationError in a RetryError.
            with pytest.raises(tenacity.RetryError) as exc_info:
                client.complete_json(
                    system="sys", user="usr", json_schema={"type": "object"}, schema_name="verdict"
                )
            assert isinstance(exc_info.value.last_attempt.exception(), LlmConfigurationError)


class TestCompleteOpenAiStyle:
    def test_complete_returns_message_content(self, monkeypatch):
        _clear_keys(monkeypatch)
        monkeypatch.setattr(llm_client.settings, "openrouter_api_key", "or-key")
        with patch("openai.OpenAI") as mock_openai:
            fake_client = MagicMock()
            fake_client.chat.completions.create.return_value = MagicMock(
                choices=[MagicMock(message=MagicMock(content="hi there"))]
            )
            mock_openai.return_value = fake_client
            client = LlmClient()
            result = client.complete(system="sys", user="usr")
        assert result == "hi there"

    def test_complete_json_parses_json_content(self, monkeypatch):
        _clear_keys(monkeypatch)
        monkeypatch.setattr(llm_client.settings, "openrouter_api_key", "or-key")
        with patch("openai.OpenAI") as mock_openai:
            fake_client = MagicMock()
            fake_client.chat.completions.create.return_value = MagicMock(
                choices=[MagicMock(message=MagicMock(content='{"applicable": false}'))]
            )
            mock_openai.return_value = fake_client
            client = LlmClient()
            result = client.complete_json(
                system="sys", user="usr", json_schema={"type": "object"}, schema_name="verdict"
            )
        assert result == {"applicable": False}

    def test_tokenrouter_complete_json_uses_its_configured_model(self, monkeypatch):
        _clear_keys(monkeypatch)
        monkeypatch.setattr(llm_client.settings, "tokenrouter_api_key", "tr-demo-key")
        monkeypatch.setattr(llm_client.settings, "tokenrouter_model", "openai:gpt-4o")
        with patch("openai.OpenAI") as mock_openai:
            fake_client = MagicMock()
            fake_client.chat.completions.create.return_value = MagicMock(
                choices=[MagicMock(message=MagicMock(content='{"verdicts": []}'))]
            )
            mock_openai.return_value = fake_client
            client = LlmClient()
            result = client.complete_json(
                system="sys", user="usr", json_schema={"type": "object"}, schema_name="verdict"
            )
        assert result == {"verdicts": []}
        assert fake_client.chat.completions.create.call_args.kwargs["model"] == "openai:gpt-4o"
        assert "response_format" not in fake_client.chat.completions.create.call_args.kwargs
        assert '"type":"object"' in fake_client.chat.completions.create.call_args.kwargs["messages"][0]["content"]

    def test_tokenrouter_complete_json_accepts_a_fenced_json_object(self, monkeypatch):
        _clear_keys(monkeypatch)
        monkeypatch.setattr(llm_client.settings, "tokenrouter_api_key", "demo-key")
        with patch("openai.OpenAI") as mock_openai:
            fake_client = MagicMock()
            fake_client.chat.completions.create.return_value = MagicMock(
                choices=[MagicMock(message=MagicMock(content='```json\n{"verdicts": []}\n```'))]
            )
            mock_openai.return_value = fake_client
            client = LlmClient()
            result = client.complete_json(
                system="sys", user="usr", json_schema={"type": "object"}, schema_name="verdict"
            )
        assert result == {"verdicts": []}


def test_get_llm_client_returns_singleton(monkeypatch):
    _clear_keys(monkeypatch)
    monkeypatch.setattr(llm_client.settings, "anthropic_api_key", "ant-key")
    with patch("anthropic.Anthropic") as mock_anthropic:
        mock_anthropic.return_value = MagicMock()
        first = llm_client.get_llm_client()
        second = llm_client.get_llm_client()
    assert first is second
    mock_anthropic.assert_called_once()
