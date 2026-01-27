import asyncio
import time
from typing import Any, Dict, Optional
from dataclasses import dataclass

import httpx

from ..config import VTConfig, get_config
from ..utils.logger import get_logger

logger = get_logger("vt_client")


class VTRateLimitError(Exception):
    pass


class VTNotFoundError(Exception):
    pass


class VTAPIError(Exception):
    pass


@dataclass
class RateLimiter:
    requests_per_minute: int
    _timestamps: list = None

    def __post_init__(self):
        self._timestamps = []

    async def acquire(self):
        now = time.time()
        self._timestamps = [t for t in self._timestamps if now - t < 60]

        if len(self._timestamps) >= self.requests_per_minute:
            wait_time = 60 - (now - self._timestamps[0])
            if wait_time > 0:
                logger.info(f"Rate limit reached, waiting {wait_time:.1f}s")
                await asyncio.sleep(wait_time)
                self._timestamps = []

        self._timestamps.append(time.time())


class VTClient:

    def __init__(self, config: Optional[VTConfig] = None):
        self.config = config or get_config().vt
        self._client: Optional[httpx.AsyncClient] = None
        self._rate_limiter = RateLimiter(self.config.rate_limit_per_minute)

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.config.api_base,
                timeout=self.config.timeout,
                headers={"x-apikey": self.config.api_key},
            )
        return self._client

    async def close(self):
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        await self._rate_limiter.acquire()

        client = await self._get_client()
        response = await client.request(method, endpoint, **kwargs)

        if response.status_code == 404:
            raise VTNotFoundError(f"Resource not found: {endpoint}")
        elif response.status_code == 429:
            raise VTRateLimitError("Rate limit exceeded")
        elif response.status_code != 200:
            raise VTAPIError(
                f"API error: {response.status_code} - {response.text}"
            )

        return response.json()

    async def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        logger.info(f"Fetching file report for {file_hash}")
        return await self._request("GET", f"/files/{file_hash}")

    async def get_file_behaviors(self, file_hash: str) -> Optional[Dict[str, Any]]:
        logger.info(f"Fetching behavior report for {file_hash}")
        try:
            return await self._request("GET", f"/files/{file_hash}/behaviours")
        except VTNotFoundError:
            logger.warning(f"No behavior data found for {file_hash}")
            return None

    async def get_full_report(self, file_hash: str) -> Dict[str, Any]:
        file_report = await self.get_file_report(file_hash)
        behaviors = await self.get_file_behaviors(file_hash)

        return {
            "file_report": file_report,
            "behaviors": behaviors,
        }

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
