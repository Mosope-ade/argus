"""
splunk_client.py — Read-only Splunk Python SDK wrapper.

All SPL queries go through this module.
No write operations exist. No user-supplied SPL is ever executed.
All queries are constructed server-side with bounded time windows.

Usage:
    client = SplunkClient()
    results = await client.search('index=botsv3 "Failed password" | head 20')

Env vars required:
    SPLUNK_HOST   — Splunk server hostname (default: localhost)
    SPLUNK_PORT   — Splunk REST API port   (default: 8089)
    SPLUNK_TOKEN  — Splunk API token (create in Settings → Tokens)
    SPLUNK_INDEX  — Default index          (default: botsv3)
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from functools import partial

import splunklib.client as splunk_client
import splunklib.results as splunk_results

log = logging.getLogger("argus.splunk")

# How long to wait for a Splunk search to complete (seconds)
_SEARCH_TIMEOUT = int(os.environ.get("SPLUNK_SEARCH_TIMEOUT", "30"))
# Poll interval while waiting for job to finish
_POLL_INTERVAL  = 0.5


class SplunkClient:
    """
    Thin async wrapper around the Splunk Python SDK.

    The SDK is synchronous. We run blocking calls in a thread pool
    via asyncio.to_thread() so FastAPI's event loop is never blocked.
    """

    def __init__(self) -> None:
        self.host  = os.environ.get("SPLUNK_HOST", "localhost")
        self.port  = int(os.environ.get("SPLUNK_PORT", "8089"))
        self.token = os.environ["SPLUNK_TOKEN"]
        self.index = os.environ.get("SPLUNK_INDEX", "botsv3")
        self._service: splunk_client.Service | None = None

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def _connect(self) -> splunk_client.Service:
        """
        Create and return a Splunk SDK Service object.
        Uses token auth (recommended over username/password).
        """
        service = splunk_client.connect(
            host=self.host,
            port=self.port,
            splunkToken=self.token,
            autologin=True,
        )
        log.info(
            "Splunk connected — host=%s port=%d index=%s",
            self.host, self.port, self.index,
        )
        return service

    def _get_service(self) -> splunk_client.Service:
        """Return cached service, reconnecting if needed."""
        if self._service is None:
            self._service = self._connect()
        return self._service

    # ------------------------------------------------------------------
    # Core search — synchronous (called from thread pool)
    # ------------------------------------------------------------------

    def _run_search_sync(self, spl: str, max_results: int = 50) -> list[dict]:
        """
        Execute a blocking one-shot Splunk search and return results.

        Args:
            spl:         Full SPL query string. Must include time bounds.
            max_results: Cap on number of returned events.

        Returns:
            List of dicts, one per result row.
        """
        service = self._get_service()

        log.info("SPL → %s", spl)

        job = service.jobs.create(
            spl,
            exec_mode="normal",   # async job — we poll until done
            count=max_results,
        )

        deadline = time.monotonic() + _SEARCH_TIMEOUT
        while not job.is_done():
            if time.monotonic() > deadline:
                job.cancel()
                raise TimeoutError(
                    f"Splunk search timed out after {_SEARCH_TIMEOUT}s: {spl}"
                )
            time.sleep(_POLL_INTERVAL)
            job.refresh()

        # Read results
        reader  = splunk_results.JSONResultsReader(
            job.results(output_mode="json", count=max_results)
        )
        rows: list[dict] = []
        for item in reader:
            if isinstance(item, dict):
                rows.append(item)

        job.cancel()  # free the job from Splunk's search head

        log.info("SPL returned %d results", len(rows))
        return rows

    # ------------------------------------------------------------------
    # Async public API
    # ------------------------------------------------------------------

    async def search(self, spl: str, max_results: int = 50) -> list[dict]:
        """
        Run a Splunk search asynchronously.

        Wraps _run_search_sync in a thread so the event loop stays free.
        All agent tools call this method.
        """
        try:
            return await asyncio.to_thread(
                self._run_search_sync, spl, max_results
            )
        except TimeoutError:
            log.error("Search timed out: %s", spl)
            return []
        except Exception as exc:
            log.error("Search failed: %s — %s", spl, exc)
            # Return empty list so the agent can continue investigating
            # rather than crashing the whole loop on one bad query
            return []

    # ------------------------------------------------------------------
    # Convenience: health check
    # ------------------------------------------------------------------

    async def ping(self) -> bool:
        """
        Return True if Splunk is reachable and the token is valid.
        Used by /api/health in Phase 2.
        """
        try:
            def _ping() -> bool:
                svc = self._get_service()
                svc.info()   # raises if auth fails
                return True
            return await asyncio.to_thread(_ping)
        except Exception as exc:
            log.warning("Splunk ping failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Convenience: fetch a single alert's raw events by SID
    # ------------------------------------------------------------------

    async def fetch_alert_events(
        self, search_id: str, max_results: int = 100
    ) -> list[dict]:
        """
        Given a Splunk search job SID (from the webhook payload),
        retrieve the events that triggered the alert.
        """
        def _fetch() -> list[dict]:
            service = self._get_service()
            try:
                job    = service.jobs[search_id]
                reader = splunk_results.JSONResultsReader(
                    job.results(output_mode="json", count=max_results)
                )
                return [item for item in reader if isinstance(item, dict)]
            except KeyError:
                log.warning("Search job %s not found in Splunk", search_id)
                return []

        try:
            return await asyncio.to_thread(_fetch)
        except Exception as exc:
            log.error("fetch_alert_events failed for SID %s: %s", search_id, exc)
            return []