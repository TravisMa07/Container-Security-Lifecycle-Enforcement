"""Small OCI fixture writer for isolated P0 adversarial cases, not a registry adapter."""

import copy
import hashlib
import json
import urllib.error
import urllib.parse

from p0_ecr import fetch
from p0_negatives import request


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def upload_blob(base, content):
    _, headers = request(base + "/blobs/uploads/", "POST")
    location = urllib.parse.urlsplit(headers["Location"])
    origin = urllib.parse.urlsplit(base)
    target = urllib.parse.urlunsplit(
        (origin.scheme, origin.netloc, location.path, location.query, "")
    )
    target += ("&" if location.query else "?") + urllib.parse.urlencode(
        {"digest": digest(content)}
    )
    request(target, "PUT", content)
    return digest(content)


def put_manifest(base, tag, raw, media_type):
    request(base + "/manifests/" + tag, "PUT", raw, media_type)
    stored, _ = fetch(base + "/manifests/" + digest(raw))
    if stored != raw:
        raise ValueError("registry fixture manifest bytes changed")


def variant(base, source, label):
    manifest = copy.deepcopy(source)
    original, _ = fetch(base + "/blobs/" + manifest["config"]["digest"])
    config = json.loads(original)
    config.setdefault("config", {}).setdefault("Labels", {})["io.csle.p0.fixture"] = (
        label
    )
    blob = json.dumps(config, sort_keys=True).encode()
    manifest["config"].update(digest=upload_blob(base, blob), size=len(blob))
    raw = json.dumps(manifest, sort_keys=True).encode()
    put_manifest(base, label, raw, manifest["mediaType"])
    return raw


def publish_bundle(base, bundle, subject_bytes, label, predicate_type):
    """Publish one fixture under a new subject, never overwrite an evidence index."""
    content = json.dumps(bundle, sort_keys=True).encode()
    descriptor = {
        "mediaType": bundle["mediaType"],
        "digest": upload_blob(base, content),
        "size": len(content),
    }
    empty = b"{}"
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": bundle["mediaType"],
        "config": {
            "mediaType": "application/vnd.oci.empty.v1+json",
            "digest": upload_blob(base, empty),
            "size": len(empty),
        },
        "layers": [descriptor],
        "subject": {
            "mediaType": json.loads(subject_bytes)["mediaType"],
            "digest": digest(subject_bytes),
            "size": len(subject_bytes),
        },
        "annotations": {
            "dev.sigstore.bundle.content": "dsse-envelope",
            "dev.sigstore.bundle.predicateType": predicate_type,
        },
    }
    raw = json.dumps(manifest, sort_keys=True).encode()
    put_manifest(base, "bundle-" + label, raw, manifest["mediaType"])
    # Both OCI 1.1 native referrers and Distribution-2 fallback are published without
    # replacing previous evidence; every fixture uses a fresh subject digest.
    tag = digest(subject_bytes).replace(":", "-")
    try:
        fetch(base + "/manifests/" + tag)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
    else:
        raise ValueError("refusing to overwrite an existing fixture evidence index")
    index = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": manifest["mediaType"],
                "size": len(raw),
                "digest": digest(raw),
                "artifactType": manifest["artifactType"],
                "annotations": manifest["annotations"],
            }
        ],
    }
    index_bytes = json.dumps(index, sort_keys=True).encode()
    put_manifest(base, tag, index_bytes, index["mediaType"])
    return {
        "bundle_sha256": digest(content),
        "artifact_digest": digest(raw),
        "subject": digest(subject_bytes),
    }
