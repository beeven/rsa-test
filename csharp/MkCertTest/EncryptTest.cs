using System;
using System.Collections.Generic;
using System.Text;
using Xunit;
using MkCert;
using Org.BouncyCastle.Crypto.Parameters;

namespace MkCertTest
{
    public class EncryptTest
    {
        private string publicKeyPem = @"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApmqhQEzLMiBikn7c5slv
tt9lNktDrzwr3tCn5N24lsZKgdJqZMd91y4oOeW/qy5CG2h9vmgmTxrmUzW2fS2K
gL9wQ0bjqXfDchiwZfJ2mpQhaSaAdMVAc4aKnvhAXE00d3NEnJTdgJJz6MAJWvUx
O9zLRrn/SiGDNiXHJwUCLuyRAVfcPjdRCsiPsVrQUkUI+gtvw6AHbKW04LTWmevH
5SycTBAdnr8JgkhbC7xaw7MFB1k9lkATVWxG8+L4zRV+lU1SLJZdkANh8Mjka/Xa
uGQ2YuvB9bKhRE0bQkXRvQRlvBuiB1fBakwIGaSyCxE2D/vM4/JjgenllvCoD18V
RwIDAQAB
-----END PUBLIC KEY-----";

        private readonly RsaKeyParameters publicKey;
        private readonly byte[] plainTextBytes = Encoding.UTF8.GetBytes("open sesame");

        public EncryptTest()
        {
            publicKey = KeyUtils.RsaKeyFromPem(publicKeyPem);
        }

        [Fact]
        public void EncryptBytesShouldReturnBytesArrayHavingLengthOf256()
        {
            var actual = Encrypt.EncryptBytes(publicKey, plainTextBytes);
            Assert.Equal(256, actual.Length);
        }

        [Fact]
        public void EncryptBytesWithCngShouldReturnBytesArrayHavingLengthOf256()
        {
            var actual = Encrypt.EncryptWithRSACng(publicKey, plainTextBytes);
            Assert.Equal(256, actual.Length);
        }

        [Fact]
        public void EncryptBytesShouldNotReturnTheSameBytes()
        {
            var actual = Encrypt.EncryptBytes(publicKey, plainTextBytes);
            var actual2 = Encrypt.EncryptBytes(publicKey, plainTextBytes);
            Assert.NotEqual(actual, actual2);
        }
    }
}
