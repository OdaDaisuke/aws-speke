import hashlib
from uuid import UUID
import base64

"""
Clear Keyを生成する
"""
class KeyGenerator:
    seed = "00112233445566778899aabbccddeeff"

    """
    https://docs.microsoft.com/en-us/playready/specifications/playready-key-seed
    PlayReadyのcontent_key生成のアルゴリズムでキー生成
    """
    def gen_content_key(self, key_id):
        key_id = UUID(key_id).bytes_le

        seed_bytes = b""
        for x in range(len(self.seed)):
            if x % 2 == 1:
                continue
            if x + 2 > len(self.seed):
                break
            l = x + 2
            seed_bytes += int(self.seed[x:l], 16).to_bytes(1, "big")

        # sha a
        # SHA of the truncatedKeySeed and the keyIdAsBytes
        sha = hashlib.sha256()
        sha.update(seed_bytes)
        sha.update(key_id)
        shaA = [c for c in sha.digest()]

        # sha b
        # SHA of the truncatedKeySeed, the keyIdAsBytes, and
        # the truncatedKeySeed again.
        sha = hashlib.sha256()
        sha.update(seed_bytes)
        sha.update(key_id)
        sha.update(seed_bytes)
        shaB = [c for c in sha.digest()]

        # sha c
        # SHA of the truncatedKeySeed, the keyIdAsBytes,
        # the truncatedKeySeed again, and the keyIdAsBytes again.
        sha = hashlib.sha256()
        sha.update(seed_bytes)
        sha.update(key_id)
        sha.update(seed_bytes)
        sha.update(key_id)
        shaC = [c for c in sha.digest()]

        # contentKey生成
        AES_KEYSIZE_128 = 16
        content_key = b""
        for i in range(AES_KEYSIZE_128):
            xorA = shaA[i] ^ shaA[i + AES_KEYSIZE_128]
            xorB = shaB[i] ^ shaB[i + AES_KEYSIZE_128]
            xorC = shaC[i] ^ shaC[i + AES_KEYSIZE_128]
            content_key += (xorA ^ xorB ^ xorC).to_bytes(1, byteorder='big')
        key = base64.b16encode(content_key)

        key_bytes = b""
        key_len = len(key)
        for x in range(key_len):
            if x % 2 == 1:
                continue
            if x + 2 > key_len:
                break
            last = x + 2
            key_bytes += int(key[x:last], 16).to_bytes(1, "big")
        return key_bytes
