package core;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSACertificateGenerator {
    
    private RSAPublicKey           publicKey;
    private RSAPrivateKey          privateKey;
    private final KeyFactory       keyFactory;
    private final KeyPairGenerator keyPairGenerator;

    public RSACertificateGenerator() throws NoSuchAlgorithmException {
        this.keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        this.keyFactory = KeyFactory.getInstance("RSA");
        this.setKeySize(1024);
    }
    
    public void setKeySize(int keysize) {
        this.keyPairGenerator.initialize(keysize);
    }

    public void generate() {
        KeyPair kp = this.keyPairGenerator.genKeyPair();
        setPublicKey(kp.getPublic());
        setPrivateKey(kp.getPrivate());
    }

    public void savePublicKeyToDisk(String pathname) throws IOException {
        byte[] keyEncoded = publicKey.getEncoded();
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyEncoded);
        FileOutputStream outputStream = new FileOutputStream(pathname);
        outputStream.write(keySpec.getEncoded());
        outputStream.close();
    }

    public void savePrivateKeyToDisk(String pathname) throws IOException {
        byte[] keyEncoded = privateKey.getEncoded();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyEncoded);
        FileOutputStream outputStream = new FileOutputStream(pathname);
        outputStream.write(keySpec.getEncoded());
        outputStream.close();
    }

    public void loadPublicKeyFromDisk(String pathname) throws IOException, InvalidKeySpecException {
        FileInputStream inputStream = new FileInputStream(pathname);
        byte[] buffer = new byte[inputStream.available()];
        inputStream.read(buffer);
        inputStream.close();
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
        setPublicKey(this.keyFactory.generatePublic(keySpec));
    }

    public void loadPrivateKeyFromDisk(String pathname) throws IOException, InvalidKeySpecException {
        FileInputStream inputStream = new FileInputStream(pathname);
        byte[] buffer = new byte[inputStream.available()];
        inputStream.read(buffer);
        inputStream.close();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
        setPrivateKey(this.keyFactory.generatePrivate(keySpec));
    }
    
    private void setPublicKey(PublicKey key) {
        publicKey = (RSAPublicKey) key;
    }
    
    private void setPrivateKey(PrivateKey key) {
        privateKey = (RSAPrivateKey) key;
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }
}
