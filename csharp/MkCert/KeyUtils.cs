using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Math;
using System.IO;

namespace MkCert
{
    public class KeyUtils
    {
        public static AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var keyPairGenerator = new Org.BouncyCastle.Crypto.Generators.RsaKeyPairGenerator();
            keyPairGenerator.Init(new RsaKeyGenerationParameters(new BigInteger("65537"),new Org.BouncyCastle.Security.SecureRandom(), 2048, 80));
            return keyPairGenerator.GenerateKeyPair();
        }


        public static string RsaKeyToPem(RsaKeyParameters keyParams)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                PemWriter writer = new PemWriter(new StreamWriter(ms));
                if(keyParams.IsPrivate)
                {
                    Pkcs8Generator generator = new Pkcs8Generator((RsaPrivateCrtKeyParameters)keyParams);
                    writer.WriteObject(generator.Generate());
                }
                else
                {
                    writer.WriteObject(keyParams);
                }
                writer.Writer.Flush();
                return System.Text.Encoding.ASCII.GetString(ms.ToArray());
            }
        }

        public static RsaKeyParameters RsaKeyFromPem(string keyPem)
        {
            using (MemoryStream ms = new MemoryStream(System.Text.Encoding.ASCII.GetBytes(keyPem)))
            {
                var pemReader = new PemReader(new StreamReader(ms));
                return pemReader.ReadObject() as RsaKeyParameters;
            }
        }
    }
}
