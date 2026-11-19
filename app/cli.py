"""Small JSON CLI. Imports are evidence, never authorization to sign."""
import argparse
import json
from pathlib import Path
import sqlite3
import sys
import urllib.error

from pydantic import ValidationError

from app.collectors.runner import execute_scan, ScannerError, verified_scanner
from app.collectors.trivy import parse_report
from app.store.db import Store


class ArgumentsError(ValueError):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ArgumentsError(message)


def arguments():
    parser = Parser(prog='csle', description=__doc__)
    parser.add_argument('--db', default='.local/csle.sqlite3', help='local SQLite evidence path')
    commands = parser.add_subparsers(dest='command', required=True, parser_class=Parser)
    database = commands.add_parser('db', help='initialize/validate migrations')
    database.add_subparsers(dest='operation', required=True, parser_class=Parser).add_parser('init')
    scan = commands.add_parser('scan', help='import untrusted reports or execute pinned Trivy')
    scans = scan.add_subparsers(dest='operation', required=True, parser_class=Parser)
    imported = scans.add_parser('import', help='import a report; does not establish executed provenance')
    imported.add_argument('report', type=Path)
    imported.add_argument('--image', required=True, help='repository@sha256:selected-manifest')
    imported.add_argument('--scanner-version')
    imported.add_argument('--db-metadata', type=Path)
    image = scans.add_parser('image', help='scan digest through explicit loopback OCI registry')
    image.add_argument('reference')
    image.add_argument('--registry-url', required=True, help='http://loopback-host:port')
    image.add_argument('--platform', default='linux/arm64')
    image.add_argument('--cache-dir', type=Path)
    listing = commands.add_parser('scans', help='query immutable scan evidence')
    listing_ops = listing.add_subparsers(dest='operation', required=True, parser_class=Parser)
    listing_ops.add_parser('list')
    listing_ops.add_parser('show').add_argument('scan_id')
    findings = commands.add_parser('findings', help='query normalized vulnerabilities, without lifecycle verdicts')
    finding_ops = findings.add_subparsers(dest='operation', required=True, parser_class=Parser)
    finding_ops.add_parser('list')
    finding_ops.add_parser('explain').add_argument('finding_id')
    commands.add_parser('doctor', help='read-only scanner/platform prerequisite verification')
    return parser


def read_bounded(path, limit):
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('input exceeds byte limit')
    return raw


def main(argv=None):
    try:
        args = arguments().parse_args(argv)
        if args.command == 'doctor':
            binary, version, digest = verified_scanner()
            result = {'scanner': 'trivy', 'version': version, 'executable_hash': digest,
                      'path': str(binary), 'integration_qualified': False}
        elif args.command == 'scan':
            # Complete validation/execution before touching the database.
            if args.operation == 'import':
                raw = read_bounded(args.report, 20 * 1024 * 1024)
                db_raw = read_bounded(args.db_metadata, 1024 * 1024) if args.db_metadata else None
                parsed = parse_report(raw, args.image, args.scanner_version, db_raw)
                context = {'provenance': 'imported'}
            else:
                parsed, raw, db_raw, resolution, execution = execute_scan(
                    args.reference, args.registry_url, args.platform, args.cache_dir)
                context = {'provenance': 'executed_local_trivy', 'resolution': resolution, 'execution': execution}
            with Store(args.db) as store:
                result = store.save_scan(parsed, raw, db_raw, **context)
        else:
            with Store(args.db) as store:
                if args.command == 'db':
                    store.initialize()
                    result = {'schema_version': 1, 'status': 'initialized'}
                elif args.command == 'scans':
                    result = store.list_scans() if args.operation == 'list' else store.get_scan(args.scan_id)
                else:
                    result = store.list_findings() if args.operation == 'list' else store.get_finding(args.finding_id)
                if result is None:
                    raise ValueError('record not found')
        print(json.dumps(result, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False))
        return 0
    except (ArgumentsError, ValueError, ValidationError, RecursionError) as error:
        # Never echo raw scanner payloads or supplied secret-bearing fields in validation errors.
        message = 'record validation failed' if isinstance(error, ValidationError) else str(error)
        print(json.dumps({'error': {'code': 'INVALID_INPUT', 'message': message}}, sort_keys=True), file=sys.stderr)
        return 2
    except (OSError, sqlite3.Error, RuntimeError, urllib.error.URLError) as error:
        message = str(error) if isinstance(error, ScannerError) else 'storage or external execution failed; inspect local prerequisites'
        print(json.dumps({'error': {'code': 'OPERATION_FAILED', 'message': message}}, sort_keys=True), file=sys.stderr)
        return 1
