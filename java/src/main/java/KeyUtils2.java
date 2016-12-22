/**
 * Created by beeven on 12/21/2016.
 */

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import sun.security.rsa.RSAKeyFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class KeyUtils2 {
    public KeyUtils2() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public KeyPair generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA","BC");
        generator.initialize(new RSAKeyGenParameterSpec(2048, new BigInteger("65537")));
        return generator.generateKeyPair();
    }

    public String RSAKeyToPem(RSAKey key) throws IOException {
        StringWriter pemStrWriter = new StringWriter();
        org.bouncycastle.util.io.pem.PemWriter pemWriter = new org.bouncycastle.util.io.pem.PemWriter(pemStrWriter);
        if(key instanceof RSAPublicKey) {
            pemWriter.writeObject(new PemObject("PUBLIC KEY", ((RSAPublicKey)key).getEncoded()));
        }
        else if(key instanceof RSAPrivateKey) {
            pemWriter.writeObject(new PemObject("PRIVATE KEY", ((RSAPrivateKey)key).getEncoded()));
        }
        pemWriter.flush();
        return pemStrWriter.toString();
    }

    public RSAKey RSAKeyFromPem(String keyPem) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
        StringReader sr = new StringReader(keyPem);
        org.bouncycastle.util.io.pem.PemReader pemReader = new org.bouncycastle.util.io.pem.PemReader(sr);
        PemObject pemObject = pemReader.readPemObject();

        if(pemObject.getType().endsWith("PUBLIC KEY")) {
            RSAKeyParameters keyParameters = (RSAKeyParameters)PublicKeyFactory.createKey(pemObject.getContent());
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(keyParameters.getModulus(),keyParameters.getExponent());
            return (RSAKey)KeyFactory.getInstance("RSA").generatePublic(keySpec);
        }
        else if(pemObject.getType().endsWith("PRIVATE KEY")) {
            RSAPrivateCrtKeyParameters keyParameter = (RSAPrivateCrtKeyParameters)PrivateKeyFactory.createKey(pemObject.getContent());
            RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(keyParameter.getModulus(), keyParameter.getPublicExponent(),
                    keyParameter.getExponent(),
                    keyParameter.getP(),keyParameter.getQ(),
                    keyParameter.getDP(), keyParameter.getDQ(),
                    keyParameter.getQInv());
            return (RSAKey)KeyFactory.getInstance("RSA").generatePrivate(keySpec);

        }
        else {
            throw new InvalidKeyException();
        }
    }

    public byte[] encrypt(RSAPublicKey publicKey, byte[] content) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(content);
    }

    public byte[] decrypt(RSAPrivateKey privateKey, byte[] cipherContent) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(cipherContent);
    }

}
