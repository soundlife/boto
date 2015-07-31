from boto.s3.key import Key as S3Key


class Key(S3Key):
    """
    Represents a key (object) in an OSS bucket.
    """

    def handle_version_headers(self, resp, force=False):
        pass

    def handle_restore_headers(self, response):
        pass
