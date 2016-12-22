using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Encodings;
using System.Security.Cryptography;

namespace MkCert
{
    public class Decrypt
    {
        public static byte[] DecryptBytes(RsaPrivateCrtKeyParameters privateKey, byte[] cipherContent)
        {
            var rsaEngine = new Org.BouncyCastle.Crypto.Engines.RsaEngine();
            var oaepEncoding = new Org.BouncyCastle.Crypto.Encodings.OaepEncoding(rsaEngine, new Sha256Digest(), new Sha256Digest(), null); // default for MGF1-SHA256
            oaepEncoding.Init(false, privateKey);
            var inputBlockSize = oaepEncoding.GetInputBlockSize();
            using (System.IO.MemoryStream ms = new System.IO.MemoryStream())
            {

                System.IO.BinaryWriter bw = new System.IO.BinaryWriter(ms);

                for (int i = 0; i < cipherContent.Length; i += inputBlockSize)
                {
                    var ciphertext = oaepEncoding.ProcessBlock(cipherContent, i, i + inputBlockSize < cipherContent.Length ? inputBlockSize : cipherContent.Length - i);
                    bw.Write(ciphertext);
                }
                bw.Flush();
                return ms.ToArray();
            }
        }

        public static byte[] DecryptBytes(RsaPrivateCrtKeyParameters privateKey, string base64EncodedCipherContent)
        {
            var cipherContent = Org.BouncyCastle.Utilities.Encoders.Base64.Decode(base64EncodedCipherContent);
            return DecryptBytes(privateKey, cipherContent);
        }

        public static byte[] DecryptWithRSACng(RsaPrivateCrtKeyParameters privateKey, byte[] cipherContent)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportParameters(new RSAParameters()
                {
                    D = privateKey.Exponent.ToByteArray(),
                    DP = privateKey.DP.ToByteArray(),
                    DQ = privateKey.DQ.ToByteArray(),
                    Modulus = privateKey.Modulus.ToByteArray(),
                    P = privateKey.P.ToByteArray(),
                    Q = privateKey.Q.ToByteArray(),
                    Exponent = privateKey.PublicExponent.ToByteArray(),
                    InverseQ = privateKey.QInv.ToByteArray()
                });

                return rsa.Decrypt(cipherContent, RSAEncryptionPadding.OaepSHA256);
            }
        }
    }
}
