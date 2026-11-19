"""P2 REST boundary cases; in-memory responses, no network."""
import io
import json
import unittest
from unittest.mock import patch
from app.collectors.kubernetes import KubeAPI, KubeError


def response(value):
    return io.BytesIO(json.dumps(value).encode())


def api():
    obj = object.__new__(KubeAPI)
    obj.namespace = 'demo'
    return obj


class KubeAPITests(unittest.TestCase):
    def test_paginated_list_is_one_consistent_snapshot(self):
        obj = api()
        pages = [response({'kind':'PodList','metadata': {'resourceVersion': 'opaque-x', 'continue': 'next'}, 'items': [{'a':1}]}), response({'kind':'PodList','metadata': {'resourceVersion': 'opaque-x'}, 'items': [{'a':2}]})]
        with patch.object(obj, '_open', side_effect=pages) as opened:
            self.assertEqual(obj.list('Pod'), ([{'kind':'Pod','apiVersion':'v1','a':1}, {'kind':'Pod','apiVersion':'v1','a':2}], 'opaque-x'))
            self.assertEqual(opened.call_args.args[1]['continue'], 'next')

    def test_partial_failed_or_inconsistent_list_never_returns_inventory(self):
        for second in [KubeError(410), response({'kind':'PodList','metadata':{'resourceVersion':'changed'}, 'items':[]})]:
            first = response({'kind':'PodList','metadata':{'resourceVersion':'x','continue':'next'}, 'items':[{}]})
            with self.subTest(second=second), patch.object(api_obj := api(), '_open', side_effect=[first, second]):
                with self.assertRaises((KubeError, ValueError)):
                    api_obj.list('Pod')

    def test_watch_410_is_not_a_workload_event(self):
        obj = api()
        with patch.object(obj, '_open', return_value=response({'type':'ERROR', 'object':{'code':410}})):
            with self.assertRaises(KubeError) as raised:
                list(obj.watch('Pod', 'old', 5))
        self.assertEqual(raised.exception.code, 410)

    def test_watch_bookmark_and_early_eof(self):
        obj = api()
        data = b'{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"rv"}}}\n'
        with patch.object(obj, '_open', return_value=io.BytesIO(data)):
            iterator = obj.watch('Pod', 'before', 5)
            self.assertEqual(next(iterator)['type'], 'BOOKMARK')
            with self.assertRaisesRegex(KubeError, 'EARLY_EOF'):
                next(iterator)

    def test_malformed_event_and_nonpositive_timeout_rejected(self):
        obj = api()
        for event in [{'type':'unknown','object':{}},{'type':'ADDED','object':False}]:
            with patch.object(obj, '_open', return_value=response(event)):
                with self.assertRaises(ValueError):
                    list(obj.watch('Pod','rv',5))
        with self.assertRaises(ValueError):
            list(obj.watch('Pod','rv',0))

    def test_remote_or_insecure_cluster_rejected_before_credentials(self):
        for server in ['https://example.com:443','http://localhost:123','https://localhost:123/path','https://u:p@localhost:123']:
            with self.subTest(server=server), self.assertRaises(ValueError):
                KubeAPI(server, '/not/a/CA', '/not/a/token', 'demo')

    def test_typed_list_supplies_omitted_item_type_metadata(self):
        obj = api()
        body = {'kind':'PodList','apiVersion':'v1','metadata':{'resourceVersion':'rv'},'items':[{'metadata':{'uid':'u'}}]}
        with patch.object(obj,'_open',return_value=response(body)):
            items, version = obj.list('Pod')
        self.assertEqual(items[0].get('kind'),'Pod')
        self.assertEqual(items[0].get('apiVersion'),'v1')
