"""Explicit read-only, CA-verified local Kubernetes REST adapter."""
import hashlib
import ipaddress
from pathlib import Path
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from app.collectors.trivy import load_document

RESOURCES = {
    'Pod': ('/api/v1', 'pods'),
    'Job': ('/apis/batch/v1', 'jobs'),
    'CronJob': ('/apis/batch/v1', 'cronjobs'),
    'Deployment': ('/apis/apps/v1', 'deployments'),
    'ReplicaSet': ('/apis/apps/v1', 'replicasets'),
    'StatefulSet': ('/apis/apps/v1', 'statefulsets'),
    'DaemonSet': ('/apis/apps/v1', 'daemonsets'),
}
MAX_BYTES = 20 * 1024 * 1024


class KubeError(RuntimeError):
    def __init__(self, code=0, reason='KUBERNETES_REQUEST_FAILED'):
        self.code = code
        self.reason = reason
        super().__init__(reason + ' (status ' + str(code) + ')')


def rv(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise ValueError('opaque resourceVersion required')
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise KubeError(0, 'KUBERNETES_REDIRECT_REFUSED')


class KubeAPI:
    def __init__(self, server, ca_file, token_file, namespace):
        url = urllib.parse.urlsplit(server)
        try:
            local = url.hostname == 'localhost' or ipaddress.ip_address(url.hostname).is_loopback
        except ValueError:
            local = False
        if (url.scheme != 'https' or not local or not url.port or url.path not in ('', '/')
                or url.username or url.password or url.query or url.fragment):
            raise ValueError('explicit loopback HTTPS Kubernetes server and port required')
        if not isinstance(namespace, str) or len(namespace) > 63 or not re.fullmatch(r'[a-z0-9]([-a-z0-9]*[a-z0-9])?', namespace):
            raise ValueError('explicit valid namespace required')
        self.server = server.rstrip('/')
        self.namespace = namespace
        self.token_file = Path(token_file)
        self._token()
        ca = Path(ca_file).read_bytes()
        self.server_id = 'sha256:' + hashlib.sha256(self.server.encode() + b'\0' + ca).hexdigest()
        context = ssl.create_default_context(cafile=str(ca_file))
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))

    def _token(self):
        if self.token_file.stat().st_mode & 0o077:
            raise ValueError('token file must be accessible only to its owner')
        with self.token_file.open('rb') as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError('token exceeds size limit')
        token = raw.decode('ascii').strip()
        if not token or any(c.isspace() for c in token):
            raise ValueError('valid token file required')
        return token

    def _path(self, kind):
        if kind not in RESOURCES:
            raise ValueError('unsupported workload kind')
        base, plural = RESOURCES[kind]
        return base + '/namespaces/' + self.namespace + '/' + plural

    def _open(self, kind, params, timeout):
        request = urllib.request.Request(self.server + self._path(kind) + '?' + urllib.parse.urlencode(params),
                                         headers={'Authorization': 'Bearer ' + self._token(), 'Accept': 'application/json'})
        try:
            return self.opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            error.close()
            raise KubeError(error.code) from None
        except (OSError, urllib.error.URLError) as error:
            raise KubeError(0, 'KUBERNETES_TRANSPORT_ERROR') from error

    def _typed_object(self, kind, value):
        if not isinstance(value, dict):
            raise ValueError('Kubernetes resource must be an object')
        version = 'v1' if kind == 'Pod' else ('batch/v1' if kind in ('Job', 'CronJob') else 'apps/v1')
        if value.get('kind', kind) != kind or value.get('apiVersion', version) != version:
            raise ValueError('Kubernetes resource type conflicts with endpoint')
        return {'kind': kind, 'apiVersion': version, **value}

    def list(self, kind):
        items, version, continuation, seen = [], None, '', set()
        total_bytes = 0
        for _ in range(21):
            params = {'limit': '500'}
            if continuation:
                params['continue'] = continuation
            with self._open(kind, params, 15) as response:
                raw = response.read(MAX_BYTES + 1)
            total_bytes += len(raw)
            if total_bytes > MAX_BYTES:
                raise ValueError('Kubernetes snapshot exceeds byte limit')
            document = load_document(raw, MAX_BYTES)
            if not isinstance(document, dict) or not isinstance(document.get('metadata'), dict) or not isinstance(document.get('items'), list):
                raise ValueError('invalid Kubernetes list document')
            current = rv(document['metadata'].get('resourceVersion'))
            if version is not None and version != current:
                raise ValueError('inconsistent paginated list resourceVersion')
            version = current
            if document.get('kind') != kind + 'List':
                raise ValueError('Kubernetes collection type conflicts with endpoint')
            items.extend(self._typed_object(kind, item) for item in document['items'])
            if len(items) > 10000:
                raise ValueError('Kubernetes list exceeds object limit')
            continuation = document['metadata'].get('continue', '')
            if not isinstance(continuation, str) or len(continuation) > 8192:
                raise ValueError('invalid list continuation')
            if not continuation:
                return items, version
            if continuation in seen:
                raise ValueError('repeated list continuation')
            seen.add(continuation)
        raise ValueError('Kubernetes list exceeds page limit')

    def watch(self, kind, resource_version, timeout_seconds):
        resource_version = rv(resource_version)
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 30:
            raise ValueError('watch timeout must be 1..30 seconds')
        params = {'watch': 'true', 'resourceVersion': resource_version, 'allowWatchBookmarks': 'true', 'timeoutSeconds': str(timeout_seconds)}
        started = time.monotonic()
        try:
            with self._open(kind, params, timeout_seconds + 10) as response:
                while True:
                    raw = response.readline(MAX_BYTES + 1)
                    if not raw:
                        if time.monotonic() - started < max(0.5, timeout_seconds - 1):
                            raise KubeError(0, 'WATCH_EARLY_EOF')
                        return
                    event = load_document(raw, MAX_BYTES)
                    if not isinstance(event, dict) or event.get('type') not in ('ADDED', 'MODIFIED', 'DELETED', 'BOOKMARK', 'ERROR') or not isinstance(event.get('object'), dict):
                        raise ValueError('malformed Kubernetes watch event')
                    if event['type'] == 'ERROR':
                        code = event['object'].get('code', 0)
                        raise KubeError(code if type(code) is int else 0, 'WATCH_STATUS_ERROR')
                    if event['type'] != 'BOOKMARK':
                        event['object'] = self._typed_object(kind, event['object'])
                    yield event
        except (OSError, urllib.error.URLError) as error:
            raise KubeError(0, 'WATCH_TRANSPORT_ERROR') from error
