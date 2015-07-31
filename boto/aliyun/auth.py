import boto
from boto.auth_handler import AuthHandler
from boto.auth import HmacKeys
from email.utils import formatdate
from .utils import canonical_string


class OSSHmacAuthV1Handler(AuthHandler, HmacKeys):
    """    Implements the HMAC request signing used by OSS."""

    capability = ['hmac-v1', 'oss']

    def __init__(self, host, config, provider):
        AuthHandler.__init__(self, host, config, provider)
        HmacKeys.__init__(self, host, config, provider)
        self._hmac_256 = None

    def update_provider(self, provider):
        super(OSSHmacAuthV1Handler, self).update_provider(provider)
        self._hmac_256 = None

    def add_auth(self, http_request, **kwargs):
        headers = http_request.headers
        method = http_request.method
        auth_path = http_request.auth_path
        if 'Date' not in headers:
            headers['Date'] = formatdate(usegmt=True)

        if self._provider.security_token:
            key = self._provider.security_token_header
            headers[key] = self._provider.security_token
        string_to_sign = canonical_string(method, auth_path,
                                          headers, None,
                                          self._provider)
        boto.log.debug('StringToSign:\n%s' % string_to_sign)
        b64_hmac = self.sign_string(string_to_sign)
        auth_hdr = self._provider.auth_header
        auth = ("%s %s:%s" % (auth_hdr, self._provider.access_key, b64_hmac))
        boto.log.debug('Signature:\n%s' % auth)
        headers['Authorization'] = auth
