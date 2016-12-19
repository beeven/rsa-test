/**
 * Created by beeven on 12/15/2016.
 */


import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.URLEncoder;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import com.sun.org.apache.xml.internal.security.utils.Base64;

public class RSATool {
    public static final String KEY_ALGORITHM = "RSA";
    public static final String ENCODING = "UTF-8";

    public static void makekeyfile(String pubkeyfile, String privatekeyfile)
            throws NoSuchAlgorithmException, FileNotFoundException, IOException {
        // KeyPairGenerator类用于生成公钥和私钥对，基于RSA算法生成对象
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        // 初始化密钥对生成器，密钥大小为1024位
        keyPairGen.initialize(1024);
        // 生成一个密钥对，保存在keyPair中
        KeyPair keyPair = keyPairGen.generateKeyPair();

        // 得到私钥
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        // 得到公钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        byte[] privKeyDer = privateKey.getEncoded();
        String privKeyPem = "-----BEGIN PRIVATE KEY-----\n" + Base64.encode(privKeyDer) + "\n-----END PRIVATE KEY-----";



        // 生成私钥
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(
                privatekeyfile));
        oos.writeObject(privateKey);
        oos.flush();
        oos.close();

        oos = new ObjectOutputStream(new FileOutputStream(pubkeyfile));
        oos.writeObject(publicKey);
        oos.flush();
        oos.close();

        System.out.println("make file ok!");
    }

    /**
     * @param k
     * @param data
     * @param encrypt 1 加密 0解密
     * @return
     * @throws NoSuchPaddingException
     * @throws Exception
     */
    public static byte[] handleData(Key k, byte[] data, int encrypt)
            throws Exception {

        if (k != null) {

            Cipher cipher = Cipher.getInstance("RSA");

            if (encrypt == 1) {
                cipher.init(Cipher.ENCRYPT_MODE, k);
                byte[] resultBytes = cipher.doFinal(data);
                return resultBytes;
            } else if (encrypt == 0) {
                cipher.init(Cipher.DECRYPT_MODE, k);
                byte[] resultBytes = cipher.doFinal(data);
                return resultBytes;
            } else {
                System.out.println("参数必须为: 1 加密 0解密");
            }
        }
        return null;
    }

    /**
     * 加密<br>
     * 用公钥加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] data, String keyFile)
            throws Exception {

        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(
                keyFile));
        RSAPublicKey pubkey = (RSAPublicKey) ois.readObject();
        ois.close();

        // 使用公钥加密私钥解密
        System.out.println("原文: " + new String(data));
        byte[] result = handleData(pubkey, data, 1);
        System.out.println("密文（ BASE64）: " + Base64.encode(result));
        return result;
    }

    /**
     * 解密<br>
     * 用私钥解密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] data, String keyFile)
            throws Exception {

        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(
                keyFile));
        RSAPrivateKey privateKey = (RSAPrivateKey) ois.readObject();
        ois.close();

        byte[] deresult = handleData(privateKey, data, 0);
        System.out.println("解密: " + new String(deresult, ENCODING));
        return deresult;
    }

    public static void main(String[] args) throws Exception {
        String inputStr = "CARGODECL||1234567890||20161213135959";
        String pubfile = "d:/temp/public.key";
        String prifile = "d:/temp/private.key";
        byte[] encryptedData = null;

        makekeyfile(pubfile, prifile);
        encryptedData = RSATool.encryptByPublicKey(inputStr.getBytes(), pubfile);
        System.out.println("密文（URLENCODE）(用于跳转至货物申报的Token参数): " + URLEncoder.encode(Base64.encode(encryptedData)));
        RSATool.decryptByPrivateKey(encryptedData, prifile);
    }

    public static void main1(String[] args) throws Exception {

        String pubfile = "d:/temp/public.key";
        String prifile = "d:/temp/private.key";

        makekeyfile(pubfile, prifile);

        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(
                pubfile));
        RSAPublicKey pubkey = (RSAPublicKey) ois.readObject();
        ois.close();

        ois = new ObjectInputStream(new FileInputStream(prifile));
        RSAPrivateKey prikey = (RSAPrivateKey) ois.readObject();
        ois.close();

        // 使用公钥加密
        String msg = "~O(∩_∩)O哈哈~";
        String enc = "UTF-8";

        // 使用公钥加密私钥解密
        System.out.println("原文: " + msg);
        byte[] result = handleData(pubkey, msg.getBytes(enc), 1);
        System.out.println("加密: " + new String(result, enc));
        byte[] deresult = handleData(prikey, result, 0);
        System.out.println("解密: " + new String(deresult, enc));

        msg = "嚯嚯";
        // 使用私钥加密公钥解密
        System.out.println("原文: " + msg);
        byte[] result2 = handleData(prikey, msg.getBytes(enc), 1);
        System.out.println("加密: " + new String(result2, enc));
        byte[] deresult2 = handleData(pubkey, result2, 0);
        System.out.println("解密: " + new String(deresult2, enc));

    }


}
