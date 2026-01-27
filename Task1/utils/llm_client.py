import json
import asyncio
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

import httpx

from ..config import LLMConfig, get_config


@dataclass
class LLMResponse:
    content: str
    usage: Dict[str, int]
    model: str
    finish_reason: str


class LLMClient:

    def __init__(self, config: Optional[LLMConfig] = None):
        self.config = config or get_config().llm
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.config.base_url,
                timeout=self.config.timeout,
                headers={
                    "Authorization": f"Bearer {self.config.api_key}",
                    "Content-Type": "application/json",
                },
            )
        return self._client

    async def close(self):
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        response_format: Optional[Dict[str, str]] = None,
    ) -> LLMResponse:
        client = await self._get_client()

        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": temperature or self.config.temperature,
            "max_tokens": max_tokens or self.config.max_tokens,
        }

        if response_format:
            payload["response_format"] = response_format

        response = await client.post("/chat/completions", json=payload)
        response.raise_for_status()

        data = response.json()
        choice = data["choices"][0]

        return LLMResponse(
            content=choice["message"]["content"],
            usage=data.get("usage", {}),
            model=data.get("model", self.config.model),
            finish_reason=choice.get("finish_reason", "stop"),
        )

    async def chat_json(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        response = await self.chat(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format={"type": "json_object"},
        )

        content = response.content.strip()

        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass

        start = content.find("{")
        end = content.rfind("}") + 1
        if start != -1 and end > start:
            try:
                return json.loads(content[start:end])
            except json.JSONDecodeError:
                pass

        try:
            fixed = self._fix_truncated_json(content[start:end] if start != -1 else content)
            return json.loads(fixed)
        except (json.JSONDecodeError, Exception) as e:
            raise ValueError(f"Failed to parse JSON response: {e}") from e

    def _fix_truncated_json(self, content: str) -> str:
        if not content:
            return "{}"

        open_braces = content.count("{") - content.count("}")
        open_brackets = content.count("[") - content.count("]")

        if content.rstrip().endswith(","):
            content = content.rstrip()[:-1]

        content += "]" * open_brackets
        content += "}" * open_braces

        return content

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
