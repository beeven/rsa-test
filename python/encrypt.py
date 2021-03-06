from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import base64

with open("../certs/public_key.pem","rb") as f:
    public_key = load_pem_public_key(f.read(), backend=default_backend())

with open("../certs/plaintext.txt", "rb") as f:
    message = f.read()

ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(),
        label=None
    )
)

b64_cipertext = base64.encodebytes(ciphertext)

with open("../certs/ciphertext.txt", "wb") as f:
    f.write(b64_cipertext)


print("Original: {0}".format(message.decode()))
print("Ciphertext: {0}".format(b64_cipertext.decode()))
