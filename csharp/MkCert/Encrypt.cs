using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Encodings;

namespace MkCert
{
    public class Encrypt
    {
        public static byte[] EncryptBytes(RsaKeyParameters publicKey, byte[] content)
        {
            var rsaEngine = new RsaEngine();
            
            var oaepEncoding = new OaepEncoding(rsaEngine,new Sha256Digest(), new Sha256Digest(),null); // MGF1-SHA256
            oaepEncoding.Init(true, publicKey);
            var inputBlockSize = oaepEncoding.GetInputBlockSize();
            using (System.IO.MemoryStream ms = new System.IO.MemoryStream())
            {
                
                System.IO.BinaryWriter bw = new System.IO.BinaryWriter(ms);
                
                int i = 0;
                for (i = 0; i < content.Length; i += inputBlockSize)
                {
                    var ciphertext = oaepEncoding.ProcessBlock(content, i, i + inputBlockSize < content.Length ? inputBlockSize : content.Length-i );
                    bw.Write(ciphertext);
                }
                bw.Flush();
                return ms.ToArray();
            }
        }

        public static string EncryptBytesAndEncodeWithBase64(RsaKeyParameters publicKey, byte[] content)
        {
            var cipherBytes = EncryptBytes(publicKey, content);
            return Org.BouncyCastle.Utilities.Encoders.Base64.ToBase64String(cipherBytes);
        }
        
    }
}
