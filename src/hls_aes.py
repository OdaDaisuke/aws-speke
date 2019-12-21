import base64
import hashlib
import os

KEY_STORE_BASE_URL = os.environ["KEY_STORE_BASE_URL"]

class HLSAesLib:
  def build_key_uri(self, content_id, kid):
    object_key = f"{content_id}/{kid}.key"
    uri = f"{KEY_STORE_BASE_URL}/{object_key}"
    return {
      "uri": base64.b64encode(uri.encode('utf-8')).decode('utf-8'),
      "key": object_key
    }

  def gen_iv(self, content_id, kid):
    m = hashlib.md5()
    m.update(kid.encode("utf-8"))
    return m.digest()
