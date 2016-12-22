/**
 * Created by beeven on 12/22/2016.
 */

import org.bouncycastle.util.encoders.Base64;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.*;

public class KeyUtils2Test {

    static KeyUtils2  target;

    @BeforeClass
    public static void initialization() {
        target = new KeyUtils2();
    }



    @Test public void testGenerateKeyPairMethod() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyPair actual = target.generateKeyPair();
        assertNotNull("GenerateKeyPair should return KeyPair",actual);
        assertTrue(actual.getPrivate() instanceof RSAPrivateKey);
    }

    @Test public void testRSAKeyToPemMethod() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
        KeyPair keyPair = target.generateKeyPair();
        String actualPublicKey = target.RSAKeyToPem((RSAKey)keyPair.getPublic());
        assertNotNull(actualPublicKey);
        assertTrue(actualPublicKey.startsWith("-----BEGIN PUBLIC KEY-----"));

        String actualPrivateKey = target.RSAKeyToPem((RSAKey)keyPair.getPrivate());
        assertNotNull(actualPrivateKey);
        assertTrue(actualPrivateKey.startsWith("-----BEGIN PRIVATE KEY-----"));
    }

    @Test public void testRSAKeyFromPemMethod() throws IOException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException {
        String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n" +
                "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCeI/J8664MyGTs\n" +
                "NyVYY55Kx/JEU0NhEhwYkWcDBWhJPUllOsWNQ3/rVd5gDU7ca86WIe0DGlS5QBv9\n" +
                "jgSTt5xVdEPc0WbFpq+KWSPxGSQvhw0tVs4oGDwmsJHgQdwXSUbkrtrX+bzacGpM\n" +
                "I/h0rangizQ/+YSGYfMq34VHJzd/mZCy0z3hgO8smEZZhcSMw1Q/mCxDO5Vggi1G\n" +
                "h+ca1+M7c+ylOSrn+zhpqGugX9gTO1HQvJqjK2HN13GTL+bBlAD+O92x3l52OemV\n" +
                "ho5zXtggsMT4N0SfkDktWaBJgOjfZrX1O6yPZ2Yh8w7X8PSaKqURj7r/ZIfslnwp\n" +
                "VUgc5gznAgMBAAECggEAJS/Izs1Q8VqSOOXC12UdjPI1qxF1T7dFehV/BrvXyRkr\n" +
                "UC2g1NYhl4Jqt2WJvNVxD+bMaCVh9On5awdhVicgEQw1BREMvL+0mbDafdBurOpy\n" +
                "E85MzircwjBVLUnval5l2FKxzYXBfhBfPqZav30y7EVvtPeEzWDtIJDNM20qZMum\n" +
                "FPdgahlZuPBEynHI0odoBNPt/BHKSS8yJS7fnrvIafF6roqt0o4x1DBb1geDGmnm\n" +
                "tK50Rkn43ZaaSeb38R8ASCmjBYOmNMXaTOueNSSyEeEBGKGU3GV8hWh3tbV2Jl5Y\n" +
                "Kh3QXJ8YGC1PsHkt7R/Z6Qv3zLZJhQaljmtkerxeyQKBgQDKCqsLnXXjIvVjyZ2t\n" +
                "BIFZXFJCYHcJEDrmMXW29HSlQh0QmpZvI9ufAF4khzltACGpy9+zS8baXE88DS/u\n" +
                "WZfz+13ql3kAQg4rUzDcmqW4GyRNt1om4Wu1cOV1NF6hoptVt/b0d/YJmuLZZk8o\n" +
                "FiNi7l1v9GrUC+Vhg6RSYKFDQwKBgQDIX85noXQeJ++ReDFC3dHgXzZijUWlmMNX\n" +
                "9AwLi3IGHTBPeX6ycXKZwPZsIq3mSI5VZngwVi0LR50KvYtksfTicyVCgO18ww/m\n" +
                "rb8Ccxh0e050mgGnQNHS6Ip5wHIQ0ixtmpvfK9WM2JG7Hsrn3q5aW9f+2edPUrGg\n" +
                "QKTvUj1rjQKBgElrHQLIglk6j99mGWUQ+QwG72FtenQRsMWLfZIxPN38q2EoO7hB\n" +
                "WIJr+MnfVa/VV2ZDTpPx2l3pI2XYCO3dIsmnM1aXGoJMfqehwGS50bSYMFYJZbox\n" +
                "Ohmh38/6atTjqPy6MARgP0j4Pqzvb55KhStjIRMYx2UsuXr5AlJpCNDPAoGANBrF\n" +
                "v6j6WwUjhP5uQOcRtnjL2aDG5aLt2Sc7Ip1mTzSz5VbAnYJmvJiy+7eg5OslKAv3\n" +
                "YQpnuDEtIyfa4ZptBZ3PqJWCLBlFP0UbEHYBe/i8lBGgMG/ooCGcMMDcaIdeyjmU\n" +
                "ItpxM6j1bGU7ekQrro+HgVwEjFoCmpt0yE7obdkCgYAJQqGXWNI6X40oLHsJMBJ4\n" +
                "tLO1qrA2PvLg4qj9d/x2LOab2QwtU8JHk3QGRVesBTa9KFSo+Xofb1fseG64FYFW\n" +
                "dPdi30XJZgGRM6QYAt4v3dkeTRHa9yWvy5SPHRqkJ9kNSc5xX/ZMCBulQnS3yPSA\n" +
                "KnzUaSCpFR+hQOXoC6idBA==\n" +
                "-----END PRIVATE KEY-----";

        RSAPrivateKey privateKey = (RSAPrivateKey)target.RSAKeyFromPem(privateKeyPem);
        assertEquals("PKCS#8",privateKey.getFormat());
        assertEquals(new BigInteger("469438065233883231200352631602206572726" +
                "700029279872723432843550032035725856883274433069696027048555514" +
                "102389928188331019839465256867449868999187536586385795304060261" +
                "949499428408944277284898829434656489976686623046973829363622342" +
                "694884425193698776290236649303354934294400477907753066637446887" +
                "684530830372000053284951373739177631953229113616426867445143730" +
                "860960831239198321167362827819637220780909689379823933394680328" +
                "687982027201613013190750430633877606220406082995740145621096890" +
                "804569244406407410553976318708675193214668696827509776812339479" +
                "313045241672989048317670129311994998888577522548835216462950750" +
                "9290032841"),privateKey.getPrivateExponent());

        String publicKeyPem = "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAniPyfOuuDMhk7DclWGOe\n" +
                "SsfyRFNDYRIcGJFnAwVoST1JZTrFjUN/61XeYA1O3GvOliHtAxpUuUAb/Y4Ek7ec\n" +
                "VXRD3NFmxaavilkj8RkkL4cNLVbOKBg8JrCR4EHcF0lG5K7a1/m82nBqTCP4dK2p\n" +
                "4Is0P/mEhmHzKt+FRyc3f5mQstM94YDvLJhGWYXEjMNUP5gsQzuVYIItRofnGtfj\n" +
                "O3PspTkq5/s4aahroF/YEztR0Lyaoythzddxky/mwZQA/jvdsd5edjnplYaOc17Y\n" +
                "ILDE+DdEn5A5LVmgSYDo32a19Tusj2dmIfMO1/D0miqlEY+6/2SH7JZ8KVVIHOYM\n" +
                "5wIDAQAB\n" +
                "-----END PUBLIC KEY-----";

        RSAPublicKey publicKey = (RSAPublicKey)target.RSAKeyFromPem(publicKeyPem);
        assertEquals("X.509", publicKey.getFormat());
        assertEquals(new BigInteger("199633784188131888412027191079837857094" +
                "216727135909536536358884812468531344381021066251954243882169766" +
                "580548496033214262846142589963805477026797440693413573855312422" +
                "213901395364590105122447696999929156989177283853283523814182840" +
                "005156320640577747723919533355356383939083278960745005049758981" +
                "754468217702224177065922033006408683603441900242276637986869367" +
                "726394700173416403148285708865938075037652522265257332561962269" +
                "380501410651427640895405310776834987535015981620059532823146668" +
                "782506632962408068947491344982222839815297801606451846656538415" +
                "522032572583111190503541454881603030801170133840532722212972138" +
                "60686990567"), publicKey.getModulus());


    }

    @Test public void testEncryptMethod() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        KeyPair keyPair = target.generateKeyPair();
        byte[] plainText = "open sesame".getBytes();
        byte[] actual = target.encrypt((RSAPublicKey)keyPair.getPublic(), plainText);
        assertNotNull(actual);
        assertEquals("OAEP SHA256 padding should have length of 256",256,actual.length);

        byte[] actual2 = target.encrypt((RSAPublicKey)keyPair.getPublic(), plainText);
        assertNotEquals("Should not output the same encrypted text even the input is the same", Base64.toBase64String(actual),Base64.toBase64String(actual2));
    }

    @Test public void testDecryptMethod() throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, IOException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n" +
                "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCeI/J8664MyGTs\n" +
                "NyVYY55Kx/JEU0NhEhwYkWcDBWhJPUllOsWNQ3/rVd5gDU7ca86WIe0DGlS5QBv9\n" +
                "jgSTt5xVdEPc0WbFpq+KWSPxGSQvhw0tVs4oGDwmsJHgQdwXSUbkrtrX+bzacGpM\n" +
                "I/h0rangizQ/+YSGYfMq34VHJzd/mZCy0z3hgO8smEZZhcSMw1Q/mCxDO5Vggi1G\n" +
                "h+ca1+M7c+ylOSrn+zhpqGugX9gTO1HQvJqjK2HN13GTL+bBlAD+O92x3l52OemV\n" +
                "ho5zXtggsMT4N0SfkDktWaBJgOjfZrX1O6yPZ2Yh8w7X8PSaKqURj7r/ZIfslnwp\n" +
                "VUgc5gznAgMBAAECggEAJS/Izs1Q8VqSOOXC12UdjPI1qxF1T7dFehV/BrvXyRkr\n" +
                "UC2g1NYhl4Jqt2WJvNVxD+bMaCVh9On5awdhVicgEQw1BREMvL+0mbDafdBurOpy\n" +
                "E85MzircwjBVLUnval5l2FKxzYXBfhBfPqZav30y7EVvtPeEzWDtIJDNM20qZMum\n" +
                "FPdgahlZuPBEynHI0odoBNPt/BHKSS8yJS7fnrvIafF6roqt0o4x1DBb1geDGmnm\n" +
                "tK50Rkn43ZaaSeb38R8ASCmjBYOmNMXaTOueNSSyEeEBGKGU3GV8hWh3tbV2Jl5Y\n" +
                "Kh3QXJ8YGC1PsHkt7R/Z6Qv3zLZJhQaljmtkerxeyQKBgQDKCqsLnXXjIvVjyZ2t\n" +
                "BIFZXFJCYHcJEDrmMXW29HSlQh0QmpZvI9ufAF4khzltACGpy9+zS8baXE88DS/u\n" +
                "WZfz+13ql3kAQg4rUzDcmqW4GyRNt1om4Wu1cOV1NF6hoptVt/b0d/YJmuLZZk8o\n" +
                "FiNi7l1v9GrUC+Vhg6RSYKFDQwKBgQDIX85noXQeJ++ReDFC3dHgXzZijUWlmMNX\n" +
                "9AwLi3IGHTBPeX6ycXKZwPZsIq3mSI5VZngwVi0LR50KvYtksfTicyVCgO18ww/m\n" +
                "rb8Ccxh0e050mgGnQNHS6Ip5wHIQ0ixtmpvfK9WM2JG7Hsrn3q5aW9f+2edPUrGg\n" +
                "QKTvUj1rjQKBgElrHQLIglk6j99mGWUQ+QwG72FtenQRsMWLfZIxPN38q2EoO7hB\n" +
                "WIJr+MnfVa/VV2ZDTpPx2l3pI2XYCO3dIsmnM1aXGoJMfqehwGS50bSYMFYJZbox\n" +
                "Ohmh38/6atTjqPy6MARgP0j4Pqzvb55KhStjIRMYx2UsuXr5AlJpCNDPAoGANBrF\n" +
                "v6j6WwUjhP5uQOcRtnjL2aDG5aLt2Sc7Ip1mTzSz5VbAnYJmvJiy+7eg5OslKAv3\n" +
                "YQpnuDEtIyfa4ZptBZ3PqJWCLBlFP0UbEHYBe/i8lBGgMG/ooCGcMMDcaIdeyjmU\n" +
                "ItpxM6j1bGU7ekQrro+HgVwEjFoCmpt0yE7obdkCgYAJQqGXWNI6X40oLHsJMBJ4\n" +
                "tLO1qrA2PvLg4qj9d/x2LOab2QwtU8JHk3QGRVesBTa9KFSo+Xofb1fseG64FYFW\n" +
                "dPdi30XJZgGRM6QYAt4v3dkeTRHa9yWvy5SPHRqkJ9kNSc5xX/ZMCBulQnS3yPSA\n" +
                "KnzUaSCpFR+hQOXoC6idBA==\n" +
                "-----END PRIVATE KEY-----";

        RSAPrivateKey privateKey = (RSAPrivateKey)target.RSAKeyFromPem(privateKeyPem);

        byte[] actual = target.decrypt(privateKey,Base64.decode("f9unO6r5tE5S5vg" +
                "UdXvF5SqIINwW1JmO99vhIye6rwGGhWVwV6IKgAD0XbUfD2lhllYdnyh0A+rXATnjqr5" +
                "qz51BsuKr1rTyjb48g29bMQ4+s/E5cFu4ia70IL1MVgF1D5FZVyuY2dPL1CuhLPCviG/" +
                "+Zl/FyAH9S6RyIPn06YB2bso+CfRi3xsNZg2MKCgHxehg9E+W7hUd5LcAGwok9lJew0m" +
                "kjPLUIMyNXeFDUxILsb1AvsDMHg2jcZMMPSsgsGUEUHWFalcYrQGLXLcw+xBLcSy3POS" +
                "UX0UQ/Ul7HY4l1/37j+KJypeh51wEAqRf+FG10sdZqt2twtPkcCZWOg=="));

        assertEquals("open sesame", new String(actual));
    }
}
