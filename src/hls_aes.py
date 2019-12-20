import base64
import hashlib

class HLSAesLib:
  def build_key_uri(self, content_id, key_id):
    uri = f"https://{content_id}/{key_id}"
    return base64.b64encode(uri.encode('utf-8')).decode('utf-8')

  def gen_iv(self, content_id, key_id):
    val = f"{content_id}{key_id}"
    return hashlib.md5(val).digest()
