import json
import logging
from datetime import UTC, datetime

logger = logging.getLogger("security.audit")


def audit_event(event: str, actor: str | None, outcome: str, request_id: str | None = None) -> None:
    # Keep audit records structured and free from tokens, passwords, and request bodies.
    record = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event": event,
        "actor": actor,
        "outcome": outcome,
        "request_id": request_id,
    }
    # Audit fields are intentionally fixed; no request payload or authorization header
    # can accidentally be serialized by this logger.
    logger.info(json.dumps(record, separators=(",", ":")))
