"""Explicit additive storage extension, then transactional historical ingestion."""

from contextlib import closing
import json

from mini_siem.ingestion.ssh_events import PARSER_VERSION
from mini_siem.storage.sqlite import connect_database, utc_now


EXTENSION_SQL = """CREATE TABLE ssh_event_details (
    event_id INTEGER PRIMARY KEY REFERENCES security_events(event_id),
    parser_version TEXT NOT NULL,
    original_fields_json TEXT NOT NULL,
    parse_status TEXT NOT NULL,
    failed_auth INTEGER NOT NULL CHECK(failed_auth IN (0,1)),
    invalid_user INTEGER NOT NULL CHECK(invalid_user IN (0,1)),
    accepted_auth INTEGER NOT NULL CHECK(accepted_auth IN (0,1)),
    auth_ambiguous INTEGER NOT NULL CHECK(auth_ambiguous IN (0,1))
)"""
EXTENSION_COLUMNS = {"event_id", "parser_version", "original_fields_json", "parse_status", "failed_auth", "invalid_user", "accepted_auth", "auth_ambiguous"}


def verify_extension(connection):
    columns = {row[1] for row in connection.execute("PRAGMA table_info(ssh_event_details)")}
    if columns != EXTENSION_COLUMNS:
        raise ValueError("Historical event storage extension absent/incompatible; explicitly run prepare-storage after review")


def prepare_storage(database):
    """Explicit opt-in only. Does not migrate or modify the four original tables."""
    with closing(connect_database(database)) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        exists = connection.execute("SELECT 1 FROM sqlite_master WHERE name = ?", ("ssh_event_details",)).fetchone()
        if not exists:
            connection.execute(EXTENSION_SQL)
        verify_extension(connection)


def persist_events(database, events, source_hash, batch_id):
    if not isinstance(batch_id, str) or not batch_id.strip() or not events:
        raise ValueError("Nonblank batch_id and validated event records required")
    timestamp = utc_now()
    inserted = 0
    with closing(connect_database(database)) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        verify_extension(connection)  # Never auto-migrate during ingestion.
        batch = connection.execute("SELECT source_sha256, record_count FROM ingestion_batches WHERE batch_id = ?", (batch_id,)).fetchone()
        if batch and (batch["source_sha256"] != source_hash or batch["record_count"] != len(events)):
            raise ValueError("Batch ID already bound to different source content")
        # A batch from another workflow must not be repurposed as raw ingestion.
        if batch:
            existing = connection.execute("""SELECT COUNT(*) FROM security_events e
                JOIN ssh_event_details d USING(event_id) WHERE e.batch_id = ?""", (batch_id,)).fetchone()[0]
            if existing != len(events):
                raise ValueError("Batch ID is not a complete historical SSH event batch")
        connection.execute("""INSERT INTO ingestion_batches VALUES (?, ?, ?, ?)
            ON CONFLICT(batch_id) DO NOTHING""", (batch_id, source_hash, len(events), timestamp))
        for event in events:
            raw_json = json.dumps(event["Original"], ensure_ascii=False, sort_keys=True)
            old = connection.execute("""SELECT e.event_id, d.parser_version, d.original_fields_json
                FROM security_events e LEFT JOIN ssh_event_details d USING(event_id)
                WHERE e.batch_id=? AND e.source_record=?""", (batch_id, event["SourceRecord"])).fetchone()
            if old:
                if old["parser_version"] != PARSER_VERSION or old["original_fields_json"] != raw_json:
                    raise ValueError("Historical record or parser version conflict; choose a new batch ID")
                continue
            cursor = connection.execute("""INSERT INTO security_events
                (batch_id,source_record,source_ip,event_type,occurred_at,ingested_at_utc)
                VALUES (?, ?, ?, ?, NULL, ?)""",
                (batch_id, event["SourceRecord"], event["SourceIP"], event["EventType"], timestamp))
            connection.execute("""INSERT INTO ssh_event_details
                (event_id,parser_version,original_fields_json,parse_status,failed_auth,invalid_user,accepted_auth,auth_ambiguous)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", (cursor.lastrowid, PARSER_VERSION, raw_json, event["ParseStatus"],
                int(event["FailedAuth"]), int(event["InvalidUser"]), int(event["AcceptedAuth"]), int(event["AuthAmbiguous"])))
            inserted += 1
    return {"records": len(events), "inserted_events": inserted, "batch_id": batch_id}
