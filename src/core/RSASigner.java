package core;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public abstract class RSASigner extends Signer {

    private final Cipher rsaCipher;
    protected RSAPublicKey publicKey;
    protected RSAPrivateKey privateKey;
    
    public RSASigner(String mode, String padding) throws NoSuchAlgorithmException, NoSuchPaddingException {
        super();
        String transformation = "RSA" + "/" + mode + "/" + padding;
        this.rsaCipher = Cipher.getInstance(transformation);
    }
    
    public RSASigner() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this("ECB", "PKCS1Padding");
    }
    
    public void initSign(PrivateKey privateKey, PublicKey publicKey) {
        super.initSign(privateKey, publicKey);
        this.privateKey = (RSAPrivateKey)privateKey;
        this.publicKey = (RSAPublicKey)publicKey;
    }

    public void initVerify(PrivateKey privateKey, PublicKey publicKey) {
        super.initVerify(privateKey, publicKey);
        this.privateKey = (RSAPrivateKey)privateKey;
        this.publicKey = (RSAPublicKey)publicKey;
    }
    
    protected byte[] encrypt(byte[] data, Key key)
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        ByteArrayInputStream dataStream = new ByteArrayInputStream(data);
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        rsaCipher.init(Cipher.ENCRYPT_MODE, key);
        
        byte buffer[] = new byte[117];
        int readed;

        while ((readed = dataStream.read(buffer)) != -1) {
            byte readedBlock[] = new byte[readed];
            System.arraycopy(buffer, 0, readedBlock, 0, readed);
            byte encryptedBlock[] = rsaCipher.doFinal(readedBlock);
            outStream.write(encryptedBlock);
        }

        return outStream.toByteArray();
    }

    protected byte[] decrypt(byte[] data, Key key)
            throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        ByteArrayInputStream dataStream = new ByteArrayInputStream(data);
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();

        rsaCipher.init(Cipher.DECRYPT_MODE, key);
        byte buffer[] = new byte[128];

        while (dataStream.read(buffer) != -1) {
            byte decryptedBlock[] = rsaCipher.doFinal(buffer);
            outStream.write(decryptedBlock);
        }

        return outStream.toByteArray();
    }
}
