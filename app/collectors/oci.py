"""Bounded P1 loopback OCI resolver; registry inventory/auth belongs to P4."""
import hashlib
import ipaddress
import json
import re
import urllib.parse
import urllib.request

ACCEPT = ', '.join([
    'application/vnd.oci.image.index.v1+json',
    'application/vnd.docker.distribution.manifest.list.v2+json',
    'application/vnd.oci.image.manifest.v1+json',
    'application/vnd.docker.distribution.manifest.v2+json',
])
DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')


def endpoint_url(value):
    url = urllib.parse.urlsplit(value)
    try:
        loopback = url.hostname == 'localhost' or ipaddress.ip_address(url.hostname).is_loopback
    except ValueError:
        loopback = False
    if (url.scheme != 'http' or not loopback or url.username or url.password
            or url.query or url.fragment or url.path not in ('', '/') or not url.port):
        raise ValueError('explicit loopback HTTP host and port required')
    return value.rstrip('/')


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('registry redirect refused')


def resolve(image_ref, endpoint, platform, fetch=None):
    from app.collectors.trivy import parse_image_ref
    origin = endpoint_url(endpoint)
    registry, repository, requested = parse_image_ref(image_ref)
    if registry != urllib.parse.urlsplit(origin).netloc:
        raise ValueError('image registry must match explicit endpoint')
    parts = platform.split('/')
    if len(parts) not in (2, 3) or not all(re.fullmatch(r'[a-z0-9][a-z0-9._-]*', x) for x in parts):
        raise ValueError('invalid platform')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def network(path, limit):
        req = urllib.request.Request(origin + path, headers={'Accept': ACCEPT})
        with opener.open(req, timeout=30) as response:
            data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError('registry document exceeds limit')
        return data

    fetch = fetch or network
    prefix = '/v2/' + repository

    def document(kind, expected, size=None):
        if not isinstance(expected, str) or not DIGEST.fullmatch(expected):
            raise ValueError('invalid descriptor digest')
        limit = 1024 * 1024 if kind == 'blobs' else 20 * 1024 * 1024
        raw = fetch(prefix + '/' + kind + '/' + expected, limit)
        if len(raw) > limit or (size is not None and (type(size) is not int or size != len(raw))):
            raise ValueError('registry descriptor size mismatch')
        if 'sha256:' + hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('registry digest mismatch')
        from app.collectors.trivy import load_document
        obj = load_document(raw, limit)
        if not isinstance(obj, dict):
            raise ValueError('registry document must be object')
        return obj

    manifest = document('manifests', requested)
    index_digest = None
    selected = requested
    if type(manifest.get('schemaVersion')) is not int or manifest['schemaVersion'] != 2:
        raise ValueError('unsupported OCI schema')
    if 'manifests' in manifest:
        index_digest = requested
        descriptors = manifest['manifests']
        if not isinstance(descriptors, list) or len(descriptors) > 1000:
            raise ValueError('invalid index descriptors')
        matches = []
        for entry in descriptors:
            if not isinstance(entry, dict) or not isinstance(entry.get('platform'), dict):
                raise ValueError('invalid platform descriptor')
            if not isinstance(entry.get('digest'), str) or not DIGEST.fullmatch(entry['digest']) or type(entry.get('size')) is not int or entry['size'] < 0:
                raise ValueError('invalid index descriptor digest or size')
            declared = entry['platform']
            if declared.get('os') == parts[0] and declared.get('architecture') == parts[1] and (len(parts) == 2 or declared.get('variant') == parts[2]):
                matches.append(entry)
        if len(matches) != 1:
            raise ValueError('platform must resolve to exactly one manifest')
        selected = matches[0]['digest']
        manifest = document('manifests', selected, matches[0]['size'])
    if type(manifest.get('schemaVersion')) is not int or manifest['schemaVersion'] != 2 or 'manifests' in manifest or not isinstance(manifest.get('layers'), list):
        raise ValueError('unsupported selected manifest')
    descriptor = manifest.get('config')
    if not isinstance(descriptor, dict) or 'size' not in descriptor:
        raise ValueError('config descriptor required')
    config = document('blobs', descriptor.get('digest'), descriptor['size'])
    if any(not isinstance(config.get(key), str) or not re.fullmatch(r'[a-z0-9][a-z0-9._-]*', config[key]) for key in ('os', 'architecture')) or ('variant' in config and (not isinstance(config['variant'], str) or not re.fullmatch(r'[a-z0-9][a-z0-9._-]*', config['variant']))):
        raise ValueError('invalid config platform fields')
    if config.get('os') != parts[0] or config.get('architecture') != parts[1] or (len(parts) == 3 and config.get('variant') != parts[2]):
        raise ValueError('config platform mismatch')
    return {'requested_reference': image_ref, 'endpoint': origin,
            'index_digest': index_digest, 'manifest_digest': selected,
            'platform_digest': selected, 'config_digest': descriptor['digest'],
            'platform': '/'.join([config['os'], config['architecture']] + ([config['variant']] if config.get('variant') else [])), 'method': 'verified_oci_manifest_and_config_bytes'}
