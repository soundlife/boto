from boto.provider import Provider
from boto.utils import unquote_v, qsa_of_interest
from boto.compat import unquote


def get_default_provider():
    return Provider('aliyun')


def canonical_string(method, path, headers, expires=None,
                     provider=None):
    """
    Generates the aliyun canonical string for the given parameters
    """
    if not provider:
        provider = get_default_provider()
    interesting_headers = {}
    for key in headers:
        lk = key.lower()
        if headers[key] is not None and \
                (lk in ['content-md5', 'content-type', 'date'] or
                 lk.startswith(provider.header_prefix)):
            interesting_headers[lk] = str(headers[key]).strip()

    # these keys get empty strings if they don't exist
    if 'content-type' not in interesting_headers:
        interesting_headers['content-type'] = ''
    if 'content-md5' not in interesting_headers:
        interesting_headers['content-md5'] = ''

    # just in case someone used this.  it's not necessary in this lib.
    if provider.date_header in interesting_headers:
        interesting_headers['date'] = ''

    # if you're using expires for query string auth, then it trumps date
    # (and provider.date_header)
    if expires:
        interesting_headers['date'] = str(expires)

    sorted_header_keys = sorted(interesting_headers.keys())

    buf = "%s\n" % method
    for key in sorted_header_keys:
        val = interesting_headers[key]
        if key.startswith(provider.header_prefix):
            buf += "%s:%s\n" % (key, val)
        else:
            buf += "%s\n" % val

    # don't include anything after the first ? in the resource...
    # unless it is one of the QSA of interest, defined above
    t = path.split('?')
    buf += unquote(t[0])

    if len(t) > 1:
        qsa = t[1].split('&')
        qsa = [a.split('=', 1) for a in qsa]
        qsa = [unquote_v(a) for a in qsa if a[0] in qsa_of_interest]
        if len(qsa) > 0:
            qsa.sort(key=lambda x: x[0])
            qsa = ['='.join(a) for a in qsa]
            buf += '?'
            buf += '&'.join(qsa)

    return buf
