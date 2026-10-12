import hashlib, json, sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from wf_peering.protocol import actions, keylog
from wf_peering.protocol.canonical import canonical_text, digest
from wf_peering.protocol.signing import b64encode, fingerprint, Signer

ORIGIN = "https://host.example"
DEVICE_SEED = bytes(range(32))
RECOVERY_SECRET = bytes(range(32, 64))
ACCOUNT_KEY = bytes(range(64, 96))


def hkdf(material: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(hashes.SHA256(), length, salt, info).derive(material)


def build() -> dict:
    canonical_cases = [
        { "b": 1, "a": [True, False, None], "c": { "z": "", "y": -7 } },
        { "text": "ä\n\t\"\\\u0001\u001f\u007f😀", "n": 9007199254740991 },
        [],
        {},
        "plain"
    ]
    device = Signer(DEVICE_SEED)
    recovery_seed = hkdf(RECOVERY_SECRET, b"users-recovery", b"users-recovery-signing-v1", 32)
    recovery = Signer(recovery_seed)
    salt = hkdf(ACCOUNT_KEY, b"users-commitment", b"users-commitment-salt-v1", 16)
    handle = keylog.account_handle(ORIGIN, 42)

    statement = { "v": 1, "account": handle, "seq": 1, "prev": keylog.GENESIS, "type": "device.bind",
                  "authority": "self", "keys": { "sig": device.public_key,
                                                 "enc": "LwGXuFrDvP-MtQxjZiIhpgN3xpT3Ud8Iu1rYkS2jyCc" },
                  "ts": 1760000000 }
    commitment = "c1:" + hashlib.sha256(salt + b"\x00" + "e1.cipher".encode()).hexdigest()
    action = { "v": 1, "account": handle, "device": fingerprint(device.public_key), "action": "users:profile.set",
               "target": "users:profile", "params": { "set": { "first_name": commitment } },
               "id": "AAAAAAAAAAAAAAAAAAAAAA", "seq": 1, "prev": actions.GENESIS, "iat": 1760000000, "exp": 1760000300 }

    return {
        "origin": ORIGIN,
        "canonical": [{ "value": case, "canonical": canonical_text(case), "sha256": digest(case) } for case in canonical_cases],
        "handle": { "uid": 42, "value": handle },
        "device": { "seed": b64encode(DEVICE_SEED), "public": device.public_key, "fingerprint": device.fingerprint },
        "recovery": { "secret": b64encode(RECOVERY_SECRET), "public": recovery.public_key },
        "account_key": { "key": b64encode(ACCOUNT_KEY), "salt": b64encode(salt), "commitment_of": "e1.cipher",
                         "commitment": commitment },
        "keylog": { "statement": statement, "hash": digest(statement),
                    "subject": device.sign(keylog.SUBJECT_CONTEXT, statement) },
        "action": { "action": action, "hash": digest(action), "signature": device.sign(actions.CONTEXT, action) },
        "state": { "values": { "first_name": commitment }, "digest": actions.state_digest({ "first_name": commitment }) }
    }


if __name__ == "__main__":
    data = build()
    Path(sys.argv[1]).write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
