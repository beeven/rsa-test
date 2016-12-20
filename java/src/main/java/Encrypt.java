/**
 * Created by beeven on 12/20/2016.
 */

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class Encrypt {
    public static byte[] EncryptBytes(RSAKeyParameters publicKeyParam, byte[] content) throws InvalidCipherTextException, IOException {
        RSAEngine rsaEngine = new RSAEngine();
        OAEPEncoding oaepEncoding = new OAEPEncoding(rsaEngine, new SHA256Digest(), new SHA256Digest(), null);
        oaepEncoding.init(true, publicKeyParam);
        int inputBlockSize = oaepEncoding.getInputBlockSize();
        ByteArrayOutputStream bo = new ByteArrayOutputStream();

        for(int i=0;i<content.length;i+=inputBlockSize){
            byte[] cipherText = oaepEncoding.processBlock(content, i, i + inputBlockSize < content.length ? inputBlockSize: content.length - i);
            bo.write(cipherText);
        }
        bo.flush();
        return bo.toByteArray();
    }

    public static String EncryptBytesAndEncodeWithBase64(RSAKeyParameters publicKeyParam, byte[] content) throws InvalidCipherTextException, IOException {
        byte[] cipherBytes = EncryptBytes(publicKeyParam, content);
        return org.bouncycastle.util.encoders.Base64.toBase64String(cipherBytes);
    }
}
