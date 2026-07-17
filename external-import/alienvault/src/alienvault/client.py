"""OpenCTI AlienVault client module."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from alienvault.models import Pulse
from OTXv2 import OTXv2
from pydantic.v1 import HttpUrl, parse_obj_as

__all__ = [
    "AlienVaultClient",
]


class AlienVaultClient:
    """AlienVault client."""

    def __init__(self, base_url: HttpUrl, api_key: str) -> None:
        """
        Initializer.
        :param base_url: Base API url.
        :param api_key: API key.
        """
        server = str(base_url).strip("/")

        self.otx = OTXv2(api_key, server=server)

    # Max pages to walk on /pulses/activity before giving up, in case the
    # newest-first ordering assumption below doesn't hold and modified_since
    # never matches. Bounds the temporary patch to a sane number of requests
    # per run instead of walking the whole OTX activity history.
    _ACTIVITY_MAX_PAGES = 50

    def get_pulses_subscribed(
        self,
        modified_since: datetime,
        limit: int = 20,
    ) -> List[Pulse]:
        """
        Get any subscribed pulses.

        Temporary workaround: fetches from /pulses/activity instead of
        /pulses/subscribed, which upstream OTX has been returning 504
        Gateway Timeout for consistently. See
        https://github.com/OpenCTI-Platform/connectors/issues/6200 (fix
        stalled on unresolved SDK issue
        https://github.com/AlienVault-OTX/OTX-Python-SDK/issues/82). Revert
        to self.otx.getsince(...) once one of those is fixed upstream.

        The activity endpoint doesn't support server-side modified_since
        filtering, so pages are walked (assumed newest first) and filtered
        here, stopping once a page contains a pulse older than
        modified_since.

        :param modified_since: Filter by results modified since this date.
        :param limit: Page size per request.
        :return: A list of pulses.
        """
        matching_pulses: List[Dict[str, Any]] = []

        next_url: Optional[str] = "/api/v1/pulses/activity"
        response = self.otx.get(next_url, limit=limit)

        for _ in range(self._ACTIVITY_MAX_PAGES):
            reached_older_pulses = False

            for pulse in response.get("results", []):
                pulse.setdefault("tlp", "white")

                try:
                    pulse_modified = datetime.fromisoformat(
                        pulse["modified"].replace("Z", "+00:00")
                    )
                except (KeyError, ValueError):
                    matching_pulses.append(pulse)
                    continue

                if pulse_modified < modified_since:
                    reached_older_pulses = True
                    break

                matching_pulses.append(pulse)

            next_url = response.get("next")
            if reached_older_pulses or not next_url:
                break

            response = self.otx.get(next_url)

        return parse_obj_as(List[Pulse], matching_pulses)
