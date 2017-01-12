package core;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import javax.crypto.NoSuchPaddingException;

public class RSAESESigner extends RSASigner {

    private final MessageDigest messageDigest;

    public RSAESESigner(String encryptMode, String encryptPadding, String hashAlgorithm) throws NoSuchAlgorithmException, NoSuchPaddingException {
        super(encryptMode, encryptPadding);
        messageDigest = MessageDigest.getInstance(hashAlgorithm);
        if (messageDigest.getDigestLength() == 0) {
            throw new IllegalArgumentException("Hash algorithm must be one that creates a hash with a fixed size");
        }
    }
    
    public RSAESESigner() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this("ECB", "PKCS1Padding", "SHA1");
    }

    protected byte[] hash(byte[] data) throws IOException {
        return messageDigest.digest(data);
    }

    public byte[] sign() throws SignatureException {
        if (state != RSAESESigner.SIGN) {
            throw new SignatureException("Need to call initSign before sign");
        }
        try {
            byte[] first = this.encrypt(buffer, publicKey);
            byte[] hash = this.hash(buffer);
            byte[] second = ArrayUtils.concat(first, hash);
            byte[] third = this.encrypt(second, privateKey);
            return this.encrypt(third, publicKey);
        } catch (Exception er) {
            throw new SignatureException(er.getMessage());
        }
    }

    public byte[] verify() throws SignatureException {
        if (state != RSAESESigner.VERIFY) {
            throw new SignatureException("Need to call initVerify before verify");
        }
        try {
            int hashSize = messageDigest.getDigestLength();
            byte[] first = this.decrypt(buffer, privateKey);
            byte[] second = this.decrypt(first, publicKey);
            if (second.length < 20) {
                throw new SignatureException("Can't find the hash.");
            }
            byte[] bufferHash = new byte[hashSize];
            System.arraycopy(second, second.length - hashSize, bufferHash, 0, hashSize);

            byte[] remaining = new byte[second.length - hashSize];
            System.arraycopy(second, 0, remaining, 0, second.length - hashSize);

            byte[] plain = this.decrypt(remaining, this.privateKey);
            byte[] plainHash = this.hash(plain);
            if (!MessageDigest.isEqual(bufferHash, plainHash)) {
                throw new SignatureException("Hashes don't match.");
            }
            return plain;

        } catch (Exception er) {
            throw new SignatureException(er.getMessage());
        }
    }
}
