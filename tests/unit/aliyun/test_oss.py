from boto.connection import HTTPRequest
from boto.s3.connection import S3Connection
from boto.auth import HmacAuthV1Handler
from boto.provider import Provider
from boto.aliyun.oss.connection import OSSConnection
from boto.aliyun.auth import OSSHmacAuthV1Handler
from tests.compat import unittest, mock
import copy


class TestAuthHandler(unittest.TestCase):

    def test_s3_auth_handler(self):
        conn = S3Connection(
            aws_access_key_id='less',
            aws_secret_access_key='more')
        self.assertIsInstance(conn._auth_handler, HmacAuthV1Handler)
        self.assertEqual(conn._required_auth_capability(), ['s3'])

    def test_oss_auth_handler(self):
        conn = OSSConnection(
            aliyun_access_key_id='less',
            aliyun_secret_access_key='more')
        self.assertIsInstance(conn._auth_handler, OSSHmacAuthV1Handler)
        self.assertEqual(conn._required_auth_capability(), ['oss'])


class TestHmacAuthV1Handler(unittest.TestCase):

    def setUp(self):
        self.s3_provider = Provider('aws', 'access_key', 'secret_key')
        self.oss_provider = Provider('aliyun', 'access_key', 'secret_key')
        self.request = HTTPRequest(
            'POST', 'http', 'example.com', 80,
            '/', None, {},
            {'Date': 'Tue, 04 Aug 2015 06:57:40 GMT'}, '')
        self.request_utf8 = HTTPRequest(
            'POST', 'http', 'example.com', 80,
            '/%E4%BA%91', None, {},
            {'Date': 'Tue, 04 Aug 2015 06:57:40 GMT'}, '')

    def test_s3_hmac_v1(self):
        auth = HmacAuthV1Handler('example.com', mock.Mock(), self.s3_provider)
        req = copy.copy(self.request)
        auth.add_auth(req)
        self.assertEqual(req.headers['Authorization'], 'AWS access_key:5xV86F00S3KvCBX4hqRf0JQn3aU=')

    def test_oss_hmac_v1(self):
        auth = OSSHmacAuthV1Handler('example.com', mock.Mock(), self.oss_provider)
        req = copy.copy(self.request)
        auth.add_auth(req)
        self.assertEqual(req.headers['Authorization'], 'OSS access_key:5xV86F00S3KvCBX4hqRf0JQn3aU=')

    def test_s3_hmac_v1_utf8(self):
        auth = HmacAuthV1Handler('example.com', mock.Mock(), self.s3_provider)
        req = copy.copy(self.request_utf8)
        auth.add_auth(req)
        self.assertEqual(req.headers['Authorization'], 'AWS access_key:O+RPWtdmJ06Hwr+jmqG8cUrngw4=')

    def test_oss_hmac_v1_utf8(self):
        auth = OSSHmacAuthV1Handler('example.com', mock.Mock(), self.oss_provider)
        req = copy.copy(self.request_utf8)
        auth.add_auth(req)
        self.assertEqual(req.headers['Authorization'], 'OSS access_key:iCgF2v7lVZzgZNG1HoPql6I6ex8=')


class TestKeyURL(unittest.TestCase):

    def test_s3_key_url(self):
        conn = S3Connection(
            aws_access_key_id='less',
            aws_secret_access_key='more')

        bucket = conn.get_bucket('bucket', validate=False)
        key = bucket.get_key('key', validate=False)
        self.assertEqual(
            key.generate_url(1438673292, expires_in_absolute=True),
            "https://bucket.s3.amazonaws.com:443/key?Signature=d%2FCBnPtvgJWHNhgGbnsMRG7IbsY%3D&Expires=1438673292&AWSAccessKeyId=less")

    def test_oss_key_url(self):
        conn = OSSConnection(
            aliyun_access_key_id='less',
            aliyun_secret_access_key='more')

        bucket = conn.get_bucket('bucket', validate=False)
        key = bucket.get_key('key', validate=False)
        self.assertEqual(
            key.generate_url(1438673292, expires_in_absolute=True),
            "https://bucket.oss.aliyuncs.com:443/key?Signature=d%2FCBnPtvgJWHNhgGbnsMRG7IbsY%3D&Expires=1438673292&OSSAccessKeyId=less")

    def test_s3_key_url_utf8(self):
        conn = S3Connection(
            aws_access_key_id='less',
            aws_secret_access_key='more')

        bucket = conn.get_bucket('bucket', validate=False)
        key = bucket.get_key('%E4%BA%91', validate=False)
        self.assertEqual(
            key.generate_url(1438673292, expires_in_absolute=True),
            "https://bucket.s3.amazonaws.com:443/%25E4%25BA%2591?Signature=t%2BBaQMweWfIESvfFjKcdwZgpa2k%3D&Expires=1438673292&AWSAccessKeyId=less")

    def test_oss_key_url_utf8(self):
        conn = OSSConnection(
            aliyun_access_key_id='less',
            aliyun_secret_access_key='more')

        bucket = conn.get_bucket('bucket', validate=False)
        key = bucket.get_key('%E4%BA%91', validate=False)
        self.assertEqual(
            key.generate_url(1438673292, expires_in_absolute=True),
            "https://bucket.oss.aliyuncs.com:443/%25E4%25BA%2591?Signature=%2BrbMj7Xqjo64UbKgqsWosaFPQPk%3D&Expires=1438673292&OSSAccessKeyId=less")
