import base64
import os
import logging
import sys
import traceback

from server_response_builder import ServerResponseBuilder

def server_handler(event, context):
    try:
        body = event['body']
        print(body)
        if event["isBase64Encoded"]:
            body = base64.b64decode(body)
        response = ServerResponseBuilder(body).get_response()
        return response
    except Exception as exception:
        t, v, tb = sys.exc_info()
        print("EXCEPTION {}".format(str(exception)))
        print(traceback.format_exception(t, v, tb))
        print(exception.__traceback__)
        return {"isBase64Encoded": False, "statusCode": 500, "headers": {"Content-Type": "text/plain"}, "body": str(exception)}
