from boto.s3.bucket import Bucket as S3Bucket
from .key import Key


class Bucket(S3Bucket):
    """Represents an Aliyun OSS bucket."""

    def __init__(self, connection=None, name=None, key_class=Key):
        super(Bucket, self).__init__(connection, name, key_class)

    def copy_key(self, new_key_name, src_bucket_name, src_key_name, *args, **kwargs):
        return super(Bucket, self).copy_key(new_key_name, '/'+src_bucket_name, src_key_name, *args, **kwargs)
