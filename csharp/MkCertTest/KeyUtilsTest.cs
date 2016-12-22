using System;
using Xunit;
using MkCert;
using Org.BouncyCastle.Crypto.Parameters;

namespace MkCertTest
{
    public class KeyUtilsTest
    {
        [Fact]
        public void RsaKeyToPemShouldGeneratePEMString()
        {
            var keyPair = KeyUtils.GenerateKeyPair();
            var actual = KeyUtils.RsaKeyToPem((RsaKeyParameters)keyPair.Public);
            Assert.StartsWith("-----BEGIN PUBLIC KEY-----", actual);

            var actual2 = KeyUtils.RsaKeyToPem((RsaPrivateCrtKeyParameters)keyPair.Private);
            Assert.StartsWith("-----BEGIN PRIVATE KEY-----", actual);
        }

        [Fact]
        public void RsaKeyFromPemShouldReturnKey()
        {
            string privateKeyPem = @"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCmaqFATMsyIGKS
ftzmyW+232U2S0OvPCve0Kfk3biWxkqB0mpkx33XLig55b+rLkIbaH2+aCZPGuZT
NbZ9LYqAv3BDRuOpd8NyGLBl8naalCFpJoB0xUBzhoqe+EBcTTR3c0SclN2AknPo
wAla9TE73MtGuf9KIYM2JccnBQIu7JEBV9w+N1EKyI+xWtBSRQj6C2/DoAdspbTg
tNaZ68flLJxMEB2evwmCSFsLvFrDswUHWT2WQBNVbEbz4vjNFX6VTVIsll2QA2Hw
yORr9dq4ZDZi68H1sqFETRtCRdG9BGW8G6IHV8FqTAgZpLILETYP+8zj8mOB6eWW
8KgPXxVHAgMBAAECggEAAh7LrSkNUbct6lXpdJtObBMOlBGDbEElAfLAoN7eUjV2
j47hwiT0ioBRDOPLfF/bgcPkDj//dPSPyLGfgJrK7/cAdCr8DZW0DMkZvkLHlhKb
Fl7iNhqpRo+JRps9Hq/xIjB6yE/xPokfJvEDbYBAP1YB1QXbpdMle9QhZHLg4z4l
GJTmf9+HGaWtgTC4AMFfA/Ttf2wo8iSNETW1Co+0qnduNZ8Wj9mMo+ix7TZVEvqz
onhjbF4FhtC2xWyl33Xo/wIiQ2OduuiuNsvU1OPypO85WY6He0LA9uN1NfqF2Zov
4aEQBzZKyYh0Sc4z11al79pncXqwucpzdZwvKobZeQKBgQDec5ENwsCfFndR30nv
yAxMrbXF204YOGccdFztIOoRzwmhC6ztUKMX4j6iJ3o8CHdIzDQvmrlKJju7hjRZ
ALNhPDx2SmrzY8a6GPWHU7mLGkiJbtVty0lkJeukiDQ4og014bVhsfoplIgh/3RA
Hg5R9Qo64QRf5saIsxzJ23Z9JQKBgQC/g6kK8wYvmfE7twSN7Db3XnDPgqNfoO40
jJqrxDKyDEvbWb4wUvr9IoqKAyToEDoDnPBatEMQDk+i/kM6SOyNRu/4itROucEQ
PjYy3viyrmXITpFCJDUMyaIfhblahfP5B8qcOayxVdgwN3iZ7D+Cw3Y7SHvmo6sa
pgGeNvg6+wKBgEyyg9y+vTMcx98Ooatuye7WJcomJvLq34JMDI4lvw6M18ETCXh5
SQI/G2FFQzvXn2kWHxgavK/4JrgtOXdGapKn9iDC38UzLZ2UZXNXRq3TThc0g5nr
cU56VJjR7U9pcCyXubYJaztS3uz56tcAhed0GSbb1mpKY0FWoCJo7J2RAoGBAIQ1
5S4c5alY8fNSfn9nke6lsOVgf16WH7wBUQnBUWofGQMd6jE8J+82uENctk7KXPJ/
lmJXzXA5IPsZ4tlK3JsPXLzNQpHypHiNKidmTHQ19ygYLSlnC4R/cj+mtnXqwamq
mlHNcw2dgLiQot5H/PRN8cItYPOxC39DGRzbP/SfAoGAeftq+seHV+d+mpn1Nglk
9sG9CdAvIhDrlTnzKpdItNGUHyPo5cnsvgTjs042+V1lgQrdyyKw+5RMWEymio26
SO88oCdU2PZdRp+8NrzGAeeDPXsanMrmAPAiGwXhR8/4w9cQmCubbBNFoijgbYB7
PomtxFeMm0if9zj/tzXDIHw=
-----END PRIVATE KEY-----";
            var actual = KeyUtils.RsaKeyFromPem(privateKeyPem);

            Assert.True(actual.IsPrivate);
        }
    }
}
