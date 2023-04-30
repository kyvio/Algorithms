from base64 import b64encode
from hashlib import sha256, sha1
from hmac import new
from random import randint

desc = b"\x01"
signature_secret_key = bytes.fromhex("ebefcf164b887da7f924c948e1fc3e40faf230eb7d491c1de1150134b8517189")
device_id_secret_key = bytes.fromhex("dcfed9e64710da3a8458298424ff88e47375")
signables = [
    "rawDeviceId",
    "rawDeviceIdTwo",
    "appType",
    "appVersion",
    "osType",
    "deviceType",
    "sId",
    "countryCode",
    "reqTime",
    "User-Agent",
    "contentRegion",
    "nonce",
    "carrierCountryCodes",
]


def request_signature(path: str, headers: dict, body: str = None) -> str:
    spec = new(
        signature_secret_key,
        path.encode(),
        sha256
    )

    for value in [headers[x] for x in signables if x in headers]:
        spec.update(value.encode())

    spec.update(body.encode() if body else bytes())
    return b64encode(desc + spec.digest()).decode()


def device_id() -> str:
    data = desc + sha1(bytes([randint(0, 255)])).digest()
    return (data + sha1(data + sha1(device_id_secret_key).digest()).digest()).hex()
