from boto.compat import urllib
from boto.s3.connection import SubdomainCallingFormat
from boto.s3.connection import S3Connection
import boto.aliyun.auth
import time
from .bucket import Bucket
from ..utils import canonical_string


class Location(object):
    DEFAULT = 'oss-cn-hangzhou'


class OSSConnection(S3Connection):

    DefaultHost = 'oss.aliyuncs.com'
    QueryString = 'Signature=%s&Expires=%d&OSSAccessKeyId=%s'

    def __init__(self, aliyun_access_key_id=None, aliyun_secret_access_key=None,
                 is_secure=True, port=None, proxy=None, proxy_port=None,
                 proxy_user=None, proxy_pass=None,
                 host=DefaultHost, debug=0, https_connection_factory=None,
                 calling_format=SubdomainCallingFormat(), path='/',
                 suppress_consec_slashes=True):
        super(OSSConnection, self).__init__(
            aliyun_access_key_id, aliyun_secret_access_key,
            is_secure, port, proxy, proxy_port, proxy_user, proxy_pass,
            host, debug, https_connection_factory, calling_format, path,
            "aliyun", Bucket,
            suppress_consec_slashes=suppress_consec_slashes)

    def _required_auth_capability(self):
        if self.anon:
            return ['anon']
        else:
            return ['oss']

    def generate_url(self, expires_in, method, bucket='', key='', headers=None,
                     query_auth=True, force_http=False, response_headers=None,
                     expires_in_absolute=False, version_id=None):
        if self._auth_handler.capability[0] == 'hmac-v4-s3':
            # Handle the special sigv4 case
            return self.generate_url_sigv4(expires_in, method, bucket=bucket,
                key=key, headers=headers, force_http=force_http,
                response_headers=response_headers, version_id=version_id)

        headers = headers or {}
        if expires_in_absolute:
            expires = int(expires_in)
        else:
            expires = int(time.time() + expires_in)
        auth_path = self.calling_format.build_auth_path(bucket, key)
        auth_path = self.get_path(auth_path)
        # optional version_id and response_headers need to be added to
        # the query param list.
        extra_qp = []
        if version_id is not None:
            extra_qp.append("versionId=%s" % version_id)
        if response_headers:
            for k, v in response_headers.items():
                extra_qp.append("%s=%s" % (k, urllib.parse.quote(v)))
        if self.provider.security_token:
            headers['x-amz-security-token'] = self.provider.security_token
        if extra_qp:
            delimiter = '?' if '?' not in auth_path else '&'
            auth_path += delimiter + '&'.join(extra_qp)
        c_string = canonical_string(method, auth_path, headers,
                                    expires, self.provider)
        b64_hmac = self._auth_handler.sign_string(c_string)
        encoded_canonical = urllib.parse.quote(b64_hmac, safe='')
        self.calling_format.build_path_base(bucket, key)
        if query_auth:
            query_part = '?' + self.QueryString % (encoded_canonical, expires,
                                                   self.aws_access_key_id)
        else:
            query_part = ''
        if headers:
            hdr_prefix = self.provider.header_prefix
            for k, v in headers.items():
                if k.startswith(hdr_prefix):
                    # headers used for sig generation must be
                    # included in the url also.
                    extra_qp.append("%s=%s" % (k, urllib.parse.quote(v)))
        if extra_qp:
            delimiter = '?' if not query_part else '&'
            query_part += delimiter + '&'.join(extra_qp)
        if force_http:
            protocol = 'http'
            port = 80
        else:
            protocol = self.protocol
            port = self.port
        return self.calling_format.build_url_base(self, protocol,
                                                  self.server_name(port),
                                                  bucket, key) + query_part
