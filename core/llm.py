from __future__ import annotations
import json
import logging
import time
from typing import Any, AsyncIterator, Optional
from urllib.parse import urlsplit

import openai
from openai import AsyncOpenAI

from .config import Config
from .usage import UsageMeter

_log = logging.getLogger(__name__)

_UNSUPPORTED_CODES = frozenset({"unsupported_parameter", "unsupported_value", "unknown_parameter"})
_UNSUPPORTED_WORDS = (
    "unsupported", "not supported", "does not support", "unrecognized", "unknown parameter",
    "unknown field", "extra inputs are not permitted", "extra_forbidden", "unexpected keyword",
    "not allowed", "not permitted",
)


def _host(api_base: Optional[str]) -> str:
    try:
        return (urlsplit(api_base or "").hostname or "").lower()
    except ValueError:
        return ""


def _is_openrouter(api_base: Optional[str]) -> bool:
    host = _host(api_base)
    return host == "openrouter.ai" or host.endswith(".openrouter.ai")


def _is_openai(api_base: Optional[str]) -> bool:
    return not api_base or _host(api_base) == "api.openai.com"


def _rejected_params(exc: Exception) -> set[str]:
    param = str(getattr(exc, "param", "") or "").lower()
    code = str(getattr(exc, "code", "") or "").lower()
    text = f"{getattr(exc, 'message', '')} {exc}".lower()
    if code not in _UNSUPPORTED_CODES and not any(w in text for w in _UNSUPPORTED_WORDS):
        return set()
    names = ("temperature", "max_tokens", "max_completion_tokens", "stream_options",
             "reasoning_effort", "reasoning", "usage")
    if param in names:
        return {param}
    first = None
    for name in names:
        for q in ("'", '"', "`"):
            pos = text.find(q + name + q)
            if pos >= 0 and (first is None or pos < first[0]):
                first = (pos, name)
    return {first[1]} if first else set()


class LLMClient:
    def __init__(self, cfg: Config, model: Optional[str] = None,
                 meter: Optional[UsageMeter] = None):
        self._client = AsyncOpenAI(
            api_key=cfg.api_key,
            base_url=cfg.api_base,
            max_retries=cfg.max_retries,
        )
        self.model = model or cfg.model
        self.meter = meter
        self._max_tokens = cfg.max_tokens
        self._temperature = cfg.temperature
        self._reasoning_effort = cfg.reasoning_effort or ""
        self._openrouter = _is_openrouter(cfg.api_base)
        self._token_param = "max_completion_tokens" if _is_openai(cfg.api_base) else "max_tokens"
        self._dropped: set[str] = set()

    def _params(self, stream: bool) -> dict:
        params: dict[str, Any] = {"model": self.model, self._token_param: self._max_tokens}
        if self._temperature is not None and "temperature" not in self._dropped:
            params["temperature"] = self._temperature
        extra: dict[str, Any] = {}
        if self._reasoning_effort and "reasoning" not in self._dropped:
            if self._openrouter:
                extra["reasoning"] = {"effort": self._reasoning_effort}
            else:
                extra["reasoning_effort"] = self._reasoning_effort
        if self._openrouter and "usage" not in self._dropped:
            extra["usage"] = {"include": True}
        if stream:
            params["stream"] = True
            if "stream_options" not in self._dropped:
                params["stream_options"] = {"include_usage": True}
        if extra:
            params["extra_body"] = extra
        return params

    def _adapt(self, exc: Exception) -> bool:
        changed = False
        for name in _rejected_params(exc):
            if name == "max_tokens" and self._token_param == "max_tokens":
                self._token_param = "max_completion_tokens"
                changed = True
            elif name == "max_completion_tokens" and self._token_param == "max_completion_tokens":
                self._token_param = "max_tokens"
                changed = True
            elif name in ("reasoning_effort", "reasoning") and "reasoning" not in self._dropped:
                self._dropped.add("reasoning")
                changed = True
            elif name in ("temperature", "stream_options", "usage") and name not in self._dropped:
                self._dropped.add(name)
                changed = True
        if changed:
            _log.info("model %s rejected a request parameter; retrying with %s and without %s",
                      self.model, self._token_param, sorted(self._dropped))
        return changed

    async def _create(self, stream: bool = False, **kwargs):
        if self.meter is not None:
            self.meter.check()
        started = time.monotonic()
        for attempt in range(5):
            params = {**self._params(stream), **kwargs}
            try:
                return await self._client.chat.completions.create(**params), started
            except (openai.BadRequestError, openai.UnprocessableEntityError) as exc:
                if attempt == 4 or not self._adapt(exc):
                    raise

    def _record(self, usage: Any, started: float) -> None:
        if self.meter is None:
            return
        seconds = time.monotonic() - started
        if usage is None:
            self.meter.record(self.model, seconds=seconds, measured=False)
            return
        details = getattr(usage, "prompt_tokens_details", None)
        out_details = getattr(usage, "completion_tokens_details", None)
        cost = getattr(usage, "cost", None)
        try:
            cost = float(cost) if cost is not None else None
        except (TypeError, ValueError):
            cost = None
        self.meter.record(
            self.model,
            prompt_tokens=int(getattr(usage, "prompt_tokens", 0) or 0),
            completion_tokens=int(getattr(usage, "completion_tokens", 0) or 0),
            cached_tokens=int(getattr(details, "cached_tokens", 0) or 0) if details else 0,
            reasoning_tokens=int(getattr(out_details, "reasoning_tokens", 0) or 0) if out_details else 0,
            seconds=seconds,
            provider_cost=cost,
        )

    @staticmethod
    def _with_system(messages: list[dict], system: Optional[str]) -> list[dict]:
        all_messages = []
        if system:
            all_messages.append({"role": "system", "content": system})
        all_messages.extend(messages)
        return all_messages

    async def complete(
        self,
        messages: list[dict],
        system: Optional[str] = None,
    ) -> str:
        resp, started = await self._create(messages=self._with_system(messages, system))
        self._record(getattr(resp, "usage", None), started)
        return resp.choices[0].message.content or ""

    async def complete_with_tools(
        self,
        messages: list[dict],
        tools: list[dict],
        system: Optional[str] = None,
        tool_choice=None,
    ) -> tuple[Optional[str], Optional[list]]:
        resp, started = await self._create(
            messages=self._with_system(messages, system),
            tools=tools,
            tool_choice=tool_choice or "auto",
        )
        self._record(getattr(resp, "usage", None), started)
        msg = resp.choices[0].message
        return msg.content, msg.tool_calls

    async def complete_stream(
        self,
        messages: list[dict],
        system: Optional[str] = None,
    ) -> AsyncIterator[str]:
        stream, started = await self._create(stream=True, messages=self._with_system(messages, system))
        usage = None
        async for chunk in stream:
            if getattr(chunk, "usage", None):
                usage = chunk.usage
            delta = chunk.choices[0].delta.content if chunk.choices else None
            if delta:
                yield delta
        self._record(usage, started)

    async def complete_json(
        self,
        messages: list[dict],
        schema: dict,
        system: Optional[str] = None,
    ) -> dict:
        resp, started = await self._create(
            messages=self._with_system(messages, system),
            response_format={
                "type": "json_schema",
                "json_schema": {"name": "result", "schema": schema, "strict": True},
            },
        )
        self._record(getattr(resp, "usage", None), started)
        raw = resp.choices[0].message.content or ""
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(raw[start:end])
            raise
