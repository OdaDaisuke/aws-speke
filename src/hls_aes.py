import base64
import hashlib
import os

KEY_STORE_URL = os.environ["KEY_STORE_URL"]

class HLSAesLib:
  def build_key_uri(self, content_id, kid):
    uri = "{}/{}/{}".format(KEY_STORE_URL, content_id, kid)
    return base64.b64encode(uri.encode('utf-8')).decode('utf-8')

  def gen_iv(self, content_id, kid):
    m = hashlib.md5()
    m.update(kid.encode("utf-8"))
    return m.digest()
