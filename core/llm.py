from __future__ import annotations
import json
from typing import Any, AsyncIterator, Optional
from urllib.parse import urlsplit
from openai import AsyncOpenAI
from .config import Config


def _is_openrouter(api_base: Optional[str]) -> bool:
    try:
        host = (urlsplit(api_base or "").hostname or "").lower()
    except ValueError:
        return False
    return host == "openrouter.ai" or host.endswith(".openrouter.ai")


class LLMClient:
    def __init__(self, cfg: Config):
        self._client = AsyncOpenAI(
            api_key=cfg.api_key,
            base_url=cfg.api_base,
        )
        self._model = cfg.model
        self._max_tokens = cfg.max_tokens
        self._temperature = cfg.temperature
        self._reasoning_effort = cfg.reasoning_effort or ""
        self._openrouter = _is_openrouter(cfg.api_base)

    def _reasoning_kwargs(self) -> dict:
        if not self._reasoning_effort:
            return {}
        if self._openrouter:
            return {"extra_body": {"reasoning": {"effort": self._reasoning_effort}}}
        return {"extra_body": {"reasoning_effort": self._reasoning_effort}}

    async def complete(
        self,
        messages: list[dict],
        system: Optional[str] = None,
    ) -> str:
        all_messages = []
        if system:
            all_messages.append({"role": "system", "content": system})
        all_messages.extend(messages)
        resp = await self._client.chat.completions.create(
            model=self._model,
            messages=all_messages,
            max_tokens=self._max_tokens,
            temperature=self._temperature,
            **self._reasoning_kwargs(),
        )
        return resp.choices[0].message.content or ""

    async def complete_with_tools(
        self,
        messages: list[dict],
        tools: list[dict],
        system: Optional[str] = None,
        tool_choice=None,
    ) -> tuple[Optional[str], Optional[list]]:
        all_messages = []
        if system:
            all_messages.append({"role": "system", "content": system})
        all_messages.extend(messages)
        resp = await self._client.chat.completions.create(
            model=self._model,
            messages=all_messages,
            tools=tools,
            tool_choice=tool_choice or "auto",
            max_tokens=self._max_tokens,
            temperature=self._temperature,
            **self._reasoning_kwargs(),
        )
        msg = resp.choices[0].message
        return msg.content, msg.tool_calls

    async def complete_stream(
        self,
        messages: list[dict],
        system: Optional[str] = None,
    ) -> AsyncIterator[str]:
        all_messages = []
        if system:
            all_messages.append({"role": "system", "content": system})
        all_messages.extend(messages)
        stream = await self._client.chat.completions.create(
            model=self._model,
            messages=all_messages,
            max_tokens=self._max_tokens,
            temperature=self._temperature,
            stream=True,
            **self._reasoning_kwargs(),
        )
        async for chunk in stream:
            delta = chunk.choices[0].delta.content if chunk.choices else None
            if delta:
                yield delta

    async def complete_json(
        self,
        messages: list[dict],
        schema: dict,
        system: Optional[str] = None,
    ) -> dict:
        all_messages = []
        if system:
            all_messages.append({"role": "system", "content": system})
        all_messages.extend(messages)
        resp = await self._client.chat.completions.create(
            model=self._model,
            messages=all_messages,
            response_format={
                "type": "json_schema",
                "json_schema": {"name": "result", "schema": schema, "strict": True},
            },
            max_tokens=self._max_tokens,
            temperature=self._temperature,
            **self._reasoning_kwargs(),
        )
        raw = resp.choices[0].message.content or ""
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(raw[start:end])
            raise
