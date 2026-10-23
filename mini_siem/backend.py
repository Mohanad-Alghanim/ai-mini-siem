"""SQLite backend commands: python -m mini_siem.backend --help."""

import argparse
import json
from pathlib import Path
import sqlite3

from mini_siem.ingestion.ssh_backend import ingest_features
from mini_siem.storage.sqlite import initialize_database, stored_statistics


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("init", "ingest", "stats"):
        subparser = commands.add_parser(command)
        subparser.add_argument("--database", type=Path, required=True)
        if command == "ingest":
            subparser.add_argument("--input", type=Path, required=True)
            subparser.add_argument("--model", type=Path, required=True)
            subparser.add_argument("--batch-id", required=True)
            subparser.add_argument("--trust-model", action="store_true", help="Only for an artifact you created/trust; joblib can execute code")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            initialize_database(args.database)
            result = {"initialized": True}
        elif args.command == "stats":
            result = stored_statistics(args.database)
        else:
            result = ingest_features(args.database, args.input, args.model, args.batch_id, trusted=args.trust_model)
    except (OSError, ValueError, TypeError, EOFError, sqlite3.Error) as exc:
        print(f"Backend command failed ({type(exc).__name__}); check database initialization, batch identity, feature validity, paths and model trust/compatibility.")
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
