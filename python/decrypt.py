from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import base64

with open("../certs/private_key.pem","rb") as f:
    private_key = load_pem_private_key(f.read(), password=None, backend=default_backend())

with open("../certs/ciphertext.txt", "rb") as f:
    b64_ciphertext = f.read()

ciphertext = base64.decodebytes(b64_ciphertext)
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(),
        label=None
    )
)

with open("../certs/plaintext.txt", "rb") as f:
    decryptedtext = f.read()

print("ciphertext: {0}".format(b64_ciphertext))
print("plain: {0}".format(plaintext.decode()))
print("original: {0}".format(decryptedtext.decode()))