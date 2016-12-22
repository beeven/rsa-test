

import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.SecureRandom;

public class KeyUtils {

    public static AsymmetricCipherKeyPair generateKeyPair() {
        RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
        keyPairGenerator.init(new RSAKeyGenerationParameters(new BigInteger("65537"),new SecureRandom(),2048,80));
        return keyPairGenerator.generateKeyPair();
    }

    public static  String RSAPrivateKeyToPem(RSAPrivateCrtKeyParameters privateKeyParam) throws IOException {
        StringWriter pemStrWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(pemStrWriter);
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKeyParam);
        pemWriter.writeObject(new PemObject("PRIVATE KEY", privateKeyInfo.getEncoded()));
        pemWriter.flush();
        return pemStrWriter.toString();
    }

    public static String RSAPublicKeyToPem(RSAKeyParameters publicKeyParam) throws IOException {
        StringWriter pemStrWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(pemStrWriter);
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKeyParam);
        pemWriter.writeObject(new PemObject("PUBLIC KEY", subjectPublicKeyInfo.getEncoded()));
        pemWriter.flush();
        return pemStrWriter.toString();
    }

    public static  RSAPrivateCrtKeyParameters RSAPrivateKeyFromPem(String privateKeyPem) throws IOException {
        StringReader sr = new StringReader(privateKeyPem);
        PemReader pemReader = new PemReader(sr);
        return (RSAPrivateCrtKeyParameters) PrivateKeyFactory.createKey(pemReader.readPemObject().getContent());
    }

    public static  RSAKeyParameters RSAPublicKeyFromPem(String publicKeyPem) throws IOException {
        StringReader sr = new StringReader(publicKeyPem);
        PemReader pemReader = new PemReader(sr);
        return (RSAKeyParameters)PublicKeyFactory.createKey(pemReader.readPemObject().getContent());
    }
}