from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key

with open("../certs/public_key.pem","rb") as f:
    public_key = load_pem_public_key(f.read(), backend=default_backend())



