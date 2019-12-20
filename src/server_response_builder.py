import base64
import xml.etree.ElementTree as element_tree
import string

from util import Util
from hls_aes import HLSAesLib
from key_generator import KeyGenerator

HLS_AES_128_SYSTEM_ID = '81376844-f976-481e-a84e-cc25d39b0b33'
HLS_AES_128_KEY_FORMAT = 'identity'
HLS_AES_128_KEY_FORMAT_VERSIONS = '1'

"""
CPIX XMLドキュメントを組み立てて返す
"""
class ServerResponseBuilder:

    def __init__(self, request_body):
        self.root = element_tree.fromstring(request_body)

        lib_factory = LibFactory(config)
        self.hls_aes_lib = HLSAesLib
        self.key_generator = KeyGenerator
        element_tree.register_namespace("cpix", "urn:dashif:org:cpix")
        element_tree.register_namespace("pskc", "urn:ietf:params:xml:ns:keyprov:pskc")
        element_tree.register_namespace("speke", "urn:aws:amazon:com:speke")
        element_tree.register_namespace("ds", "http://www.w3.org/2000/09/xmldsig#")
        element_tree.register_namespace("enc", "http://www.w3.org/2001/04/xmlenc#")

    def fixup_document(self, drm_system, system_id, kid, content_id, iv):
        """
        Update the returned XML document based on the specified system ID
        """
        if system_id.lower() == HLS_AES_128_SYSTEM_ID.lower():
            ext_x_key = self.hls_aes_lib.build_key_URI(content_id, kid, iv)
            drm_system.find("{urn:dashif:org:cpix}URIExtXKey").text = base64.b64encode(ext_x_key.encode("utf-8")).decode("utf-8")
            drm_system.find("{urn:aws:amazon:com:speke}KeyFormat").text = base64.b64encode(HLS_AES_128_KEY_FORMAT).decode("utf-8")
            drm_system.find("{urn:aws:amazon:com:speke}KeyFormatVersions").text = base64.b64encode(HLS_AES_128_KEY_FORMAT_VERSIONS).decode("utf-8")
            self.safe_remove(drm_system, "{urn:dashif:org:cpix}ContentProtectionData")
            self.safe_remove(drm_system, "{urn:aws:amazon:com:speke}ProtectionHeader")
            self.safe_remove(drm_system, "{urn:dashif:org:cpix}PSSH")
        else:
            raise Exception("Invalid system ID {}".format(system_id))

    def fill_request(self):
        content_id = self.root.get("id")
        system_ids = {}

        content_keys = self.root.findall("./{urn:dashif:org:cpix}ContentKeyList/{urn:dashif:org:cpix}ContentKey")

        for drm_system in self.root.findall("./{urn:dashif:org:cpix}DRMSystemList/{urn:dashif:org:cpix}DRMSystem"):
            kid = drm_system.get("kid")
            system_id = drm_system.get("systemId")
            system_ids[system_id] = kid
            logging.info("ContentID")
            logging.info(content_id)
            iv = base64.b64encode(self.hls_aes_lib.gen_iv(content_id, kid)).decode('utf-8')
            self.fixup_document(drm_system, system_id, kid, content_id, iv)

        for content_key_tag in content_keys:
            init_vector = content_key_tag.get("explicitIV")
            # explicitIVはHLS AESまたはSAMPLE AES(Fairplay)の場合必要
            if init_vector is None and system_ids.get(config.HLS_AES_128_SYSTEM_ID, False) == kid:
                content_key_tag.set('explicitIV', base64.b64encode(self.hls_aes_lib.gen_iv(content_id, kid)).decode('utf-8'))

            data = element_tree.SubElement(content_key_tag, "{urn:dashif:org:cpix}Data")
            secret = element_tree.SubElement(data, "{urn:ietf:params:xml:ns:keyprov:pskc}Secret")
            plain_value = element_tree.SubElement(secret, "{urn:ietf:params:xml:ns:keyprov:pskc}PlainValue")
            key = self.key_generator.gen_content_key(key)
            # キーを指定
            plain_value.text = base64.b64encode(key).decode('utf-8')

    def get_response(self):
        """
        Get the key request response as an HTTP response.
        """
        self.fill_request()
        return {
            "isBase64Encoded": True,
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/xml",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
                "Speke-User-Agent": "oda-key-server"
            },
            "body": base64.b64encode(element_tree.tostring(self.root)).decode('utf-8')
        }

    def safe_remove(self, element, match):
        elm_instance = element.find(match)
        if elm_instance is not None:
            element.remove(elm_instance)
        else:
            logging.warning("not match xml", match)
