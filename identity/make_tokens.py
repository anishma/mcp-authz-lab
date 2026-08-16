"""Generate the lab's static identity fixtures: an RSA keypair, a JWKS file
for the gateway, and long-lived JWTs for the two lab personas.

These are TEST credentials for a self-contained lab. Never reuse outside it.
Run: python make_tokens.py   (writes jwks.json and tokens/*.jwt next to it)
"""

import json
import pathlib
import time

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

HERE = pathlib.Path(__file__).parent
ISSUER = "https://lab-issuer.payflow.example"
AUDIENCE = "payflow-mcp"
KID = "lab-key-1"

PERSONAS = {
    "alice": {"sub": "alice", "name": "Alice Rivera", "department": "finance"},
    "bob": {"sub": "bob", "name": "Bob Chen", "department": "engineering"},
}


def main() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    (HERE / "issuer_private_key.pem").write_bytes(priv_pem)

    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
    (HERE / "jwks.json").write_text(json.dumps({"keys": [jwk]}, indent=2))

    tokens_dir = HERE / "tokens"
    tokens_dir.mkdir(exist_ok=True)
    now = int(time.time())
    for name, claims in PERSONAS.items():
        payload = {
            **claims,
            "iss": ISSUER,
            "aud": AUDIENCE,
            "iat": now,
            "exp": now + 10 * 365 * 24 * 3600,  # lab fixture: 10 years
        }
        token = jwt.encode(payload, priv_pem, algorithm="RS256", headers={"kid": KID})
        (tokens_dir / f"{name}.jwt").write_text(token)
        print(f"wrote tokens/{name}.jwt")
    print("wrote jwks.json")


if __name__ == "__main__":
    main()
