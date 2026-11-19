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
    inventory = commands.add_parser('inventory', help='namespaced Kubernetes history and coverage')
    inventory_ops = inventory.add_subparsers(dest='operation', required=True, parser_class=Parser)
    collect = inventory_ops.add_parser('collect', help='read-only local list/watch; explicit CA/token required')
    for name in ('cluster', 'namespace', 'server', 'ca', 'token-file'):
        collect.add_argument('--' + name, required=True)
    collect.add_argument('--duration', type=float)
    collect.add_argument('--reconcile-seconds', type=int, default=30)
    collect.add_argument('--watch-seconds', type=int, default=5)
    for operation in ('workloads', 'observations', 'events', 'snapshots', 'gaps'):
        query = inventory_ops.add_parser(operation)
        query.add_argument('--cluster', required=True)
        query.add_argument('--namespace')
    def assessment_options(command):
        command.add_argument('finding_id')
        command.add_argument('--cluster', required=True)
        command.add_argument('--namespace', action='append', required=True)
        command.add_argument('--replacement')
        command.add_argument('--at')
        command.add_argument('--inventory-max-age-seconds', type=int, default=30)
        command.add_argument('--scan-max-age-seconds', type=int, default=86400)
        command.add_argument('--db-max-age-seconds', type=int, default=86400)
    assessment_options(finding_ops.add_parser('assess', help='derive evidence-bound lifecycle state'))
    remediation = commands.add_parser('remediation', help='verify an explicit scoped replacement')
    remediation_ops = remediation.add_subparsers(dest='operation', required=True, parser_class=Parser)
    verify = remediation_ops.add_parser('verify')
    assessment_options(verify)
    lifecycle = commands.add_parser('lifecycle', help='query immutable lifecycle assessments')
    lifecycle.add_subparsers(dest='operation', required=True, parser_class=Parser).add_parser('image').add_argument('digest')
    assessments = commands.add_parser('assessments', help='inspect a persisted assessment')
    assessments.add_subparsers(dest='operation', required=True, parser_class=Parser).add_parser('show').add_argument('assessment_id')
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
        elif args.command in ('remediation', 'lifecycle', 'assessments') or (args.command == 'findings' and args.operation == 'assess'):
            from app.store.assessments import AssessmentStore
            if args.command == 'remediation' and not args.replacement:
                raise ValueError('explicit replacement digest required')
            with AssessmentStore(args.db) as store:
                if args.command == 'lifecycle':
                    result = store.list_assessments(args.digest)
                elif args.command == 'assessments':
                    result = store.get_assessment(args.assessment_id)
                    if result is None:
                        raise ValueError('assessment not found')
                else:
                    result = store.assess(args.finding_id, args.cluster, args.namespace, args.replacement, args.at,
                                          args.inventory_max_age_seconds, args.scan_max_age_seconds, args.db_max_age_seconds)
        elif args.command == 'inventory':
            from app.store.inventory import InventoryStore
            if args.operation == 'collect':
                from app.collectors.kubernetes import KubeAPI
                from app.collectors.lifecycle import Collector
                api = KubeAPI(args.server, args.ca, args.token_file, args.namespace)
                result = Collector(api, args.db, args.cluster, args.namespace,
                                   args.reconcile_seconds, args.watch_seconds).run(args.duration)
                if result['errors']:
                    raise RuntimeError('collection encountered gaps; inspect inventory gaps')
            else:
                with InventoryStore(args.db) as store:
                    method = store.current if args.operation == 'workloads' else getattr(store, args.operation)
                    result = method(args.cluster, args.namespace)
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
                    result = {'schema_version': store.connection.execute('PRAGMA user_version').fetchone()[0], 'status': 'initialized'}
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
