/**
 * Created by beeven on 12/21/2016.
 */

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class KeyUtils2 {
    public KeyUtils2() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public KeyPair generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA","BC");
        generator.initialize(2048);
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
        pemStrWriter.flush();
        return pemStrWriter.toString();
    }

    public byte[] Encrypt(RSAPublicKey publicKey, byte[] content) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(content);
    }

}
