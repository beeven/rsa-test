import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

/**
 * Created by beeven on 12/20/2016.
 */

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class Decrypt {

    public static byte[] DecryptBytes(RSAPrivateCrtKeyParameters privateKeyParam, byte[] cipherContent) throws InvalidCipherTextException, IOException {
        RSAEngine rsaEngine = new RSAEngine();
        OAEPEncoding oaepEncoding = new OAEPEncoding(rsaEngine, new SHA256Digest(), new SHA256Digest(), null);
        oaepEncoding.init(false, privateKeyParam);
        int inputBlockSize = oaepEncoding.getInputBlockSize();
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        for(int i=0;i< cipherContent.length; i+=inputBlockSize) {
            byte[] decryptedBytes = oaepEncoding.processBlock(cipherContent, i, i + inputBlockSize < cipherContent.length ? inputBlockSize: cipherContent.length - i);
            bo.write(decryptedBytes);
        }
        bo.flush();
        return bo.toByteArray();
    }

    public static byte[] DecryptBytes(RSAPrivateCrtKeyParameters privateKeyParam, String base64EncodedCipherContent) throws IOException, InvalidCipherTextException {
        byte[] cipherContent = org.bouncycastle.util.encoders.Base64.decode(base64EncodedCipherContent);
        return DecryptBytes(privateKeyParam, cipherContent);
    }
}
