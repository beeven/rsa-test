using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.IO;
using Org.BouncyCastle.Crypto.Parameters;


namespace MkCert
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var keyPair = KeyUtils.GenerateKeyPair();
            var publicKeyPem = KeyUtils.RsaPublicKeyToPem((RsaKeyParameters)keyPair.Public);
            var privateKeyPem = KeyUtils.RsaPrivateKeyToPem((RsaPrivateCrtKeyParameters)keyPair.Private);
            File.WriteAllText(@"d:\dev\rsa-test\certs\private_key.pem", privateKeyPem);
            File.WriteAllText(@"d:\dev\rsa-test\certs\public_key.pem", publicKeyPem);

            var publicKey = KeyUtils.RsaPublicKeyFromPem(File.ReadAllText(@"d:\dev\rsa-test\certs\public_key.pem"));
            var privateKey = KeyUtils.RsaPrivateKeyFromPem(File.ReadAllText(@"d:\dev\rsa-test\certs\private_key.pem"));

            var plainText = File.ReadAllBytes(@"d:\dev\rsa-test\certs\plaintext.txt");
            var cipherText = Encrypt.EncryptBytesAndEncodeWithBase64(publicKey, plainText);
            Console.WriteLine("Plain: {0}", System.Text.Encoding.UTF8.GetString(plainText));
            Console.WriteLine("Cipher text: {0}", cipherText);
            File.WriteAllText(@"d:\dev\rsa-test\certs\ciphertext.txt", cipherText);

            var decryptedText = Decrypt.DecryptBytes(privateKey, cipherText);
            Console.WriteLine("Decrypted text: {0}", System.Text.Encoding.UTF8.GetString(decryptedText));

        }
    }
}
