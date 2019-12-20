import string
import random
import hashlib
import base64

class Util:
  # strsを全部hex binaryに
  @staticmethod
  def str_to_hex_binary(s):
    slen = len(s)
    seed_bytes = b""
    for x in range(slen):
      if x % 2 == 1:
          continue
      if x + 2 > slen:
          break
      last = x + 2
      seed_bytes += int(s[x:last], 16).to_bytes(1, "big")
    return seed_bytes
  
  @staticmethod
  def bin_to_hex_str(s):
    hex_arr = ["{:02x}".format(x) for x in s]
    return "".join(hex_arr)

  # decimal numberを文字列のhexに
  @staticmethod
  def to_hex_str(s):
    return str(hex(s)).replace("0x", "")
