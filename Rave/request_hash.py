from base64 import b64encode
from hashlib import sha256
from hmac import new

secret_key = "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2".encode()


def request_hash(current_time, session_id, content_length):
    message = f"{current_time}:{session_id}:{content_length}"
    mac = new(secret_key, message.encode(), sha256).digest()
    return b64encode(mac).decode()
