"""DNS watcher helpers for split-engine."""

from __future__ import annotations

from dataclasses import dataclass

from engine.storage import upsert_domain_observation


@dataclass(slots=True)
class DomainObservation:
    domain: str
    peer: str | None = None
    timestamp: str | None = None


def ingest_dns_event(event: dict) -> DomainObservation | None:
    """Normalize a dnsmasq event into a domain observation and persist it."""
    domain = (event.get("domain") or "").strip().lower().rstrip(".")
    if not domain:
        return None

    observation = DomainObservation(
        domain=domain,
        peer=event.get("peer"),
        timestamp=event.get("timestamp"),
    )
    upsert_domain_observation(observation.domain, peer=observation.peer, seen_at=observation.timestamp)
    return observation
