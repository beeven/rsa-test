﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Encodings;

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

                int i = 0;
                for (i = 0; i < cipherContent.Length; i += inputBlockSize)
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
    }
}