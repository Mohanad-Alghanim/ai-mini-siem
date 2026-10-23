"""Conservative historical SSH parsing; no timestamp/year or identity inference."""

import hashlib
from ipaddress import ip_address
from pathlib import Path
import re
import tempfile

from mini_siem.ingestion.csv_loader import load_csv


COLUMNS = ("LineId", "Date", "Day", "Time", "Component", "Pid", "Content", "EventId", "EventTemplate")
PARSER_VERSION = "ssh-historical-v1"
# Only explicit remote-peer contexts count as SourceIP evidence.
PEER = re.compile(r"(?:\bfrom\s+|\brhost=|\bclosed by\s+)(\S+)", re.IGNORECASE)
FAILURE = re.compile(r"^Failed (?:password|publickey|keyboard-interactive|none|hostbased)\b|\bauthentication failure\b", re.IGNORECASE)
ACCEPTED = re.compile(r"^Accepted (?:password|publickey|keyboard-interactive|none|hostbased)\b", re.IGNORECASE)
INVALID = re.compile(r"\binvalid user\b", re.IGNORECASE)


def parse_message(content):
    candidates, invalid = set(), False
    for token in PEER.findall(content):
        try:
            candidates.add(str(ip_address(token)))
        except ValueError:
            invalid = True
    if invalid:
        status, source = "invalid_peer", None
    elif len(candidates) > 1:
        status, source = "ambiguous_peer", None
    elif candidates:
        status, source = "supported_peer", next(iter(candidates))
    else:
        # Bare address-like evidence is not enough to establish a remote peer.
        address_like = False
        for token in re.split(r"[\s=\[\](),;]+", content):
            try:
                ip_address(token)
                address_like = True
            except ValueError:
                pass
        status, source = ("unsupported_ip_context" if address_like else "no_ip_evidence"), None
    failed, accepted = bool(FAILURE.search(content)), bool(ACCEPTED.search(content))
    return {"SourceIP": source, "ParseStatus": status, "FailedAuth": failed,
            "InvalidUser": bool(INVALID.search(content)), "AcceptedAuth": accepted,
            "AuthAmbiguous": failed and accepted}


def load_events(path):
    """Snapshot exact bytes for identity; reuse strict CSV loading unchanged."""
    content = Path(path).read_bytes()
    with tempfile.TemporaryDirectory(prefix="mini-siem-ssh-") as folder:
        snapshot = Path(folder) / "events.csv"
        snapshot.write_bytes(content)
        frame = load_csv(snapshot)
    if set(COLUMNS) - set(frame):
        raise ValueError("Missing required historical SSH columns")
    if frame.empty:
        raise ValueError("Historical SSH CSV must contain event records")
    events = []
    for position, (_, row) in enumerate(frame.iterrows(), 1):
        raw = {column: str(row[column]) for column in frame.columns}
        if not raw["LineId"].isdigit() or int(raw["LineId"]) < 1 or not raw["Content"].strip():
            raise ValueError("Each event needs a positive integral LineId and nonblank Content")
        if not raw["EventId"].strip() and not raw["EventTemplate"].strip():
            raise ValueError("Each event needs an EventId or EventTemplate")
        event_type = ("id:" + raw["EventId"]) if raw["EventId"].strip() else ("template:" + raw["EventTemplate"])
        events.append({"SourceRecord": position, "Original": raw, "EventType": event_type,
                       **parse_message(raw["Content"])})
    return events, hashlib.sha256(content).hexdigest()
