"""Sentinel: autonomous, multi-agent CWE-coverage pentesting platform.

Every scan is gated by sentinel.phase0 (ownership + environment verification)
and every dispatch call is gated by sentinel.security.guardrails. Those two
modules are the only things standing between an LLM agent and a live target;
they are plain code, not prompts, and are exercised directly by tests/.
"""

__version__ = "0.1.0"
