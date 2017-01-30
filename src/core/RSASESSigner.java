package core;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import javax.crypto.NoSuchPaddingException;

public class RSASESSigner extends RSASigner {
    
    private final MessageDigest messageDigest;

    public RSASESSigner(String encryptMode, String encryptPadding, String hashAlgorithm) throws NoSuchAlgorithmException, NoSuchPaddingException {
        super(encryptMode, encryptPadding);
        messageDigest = MessageDigest.getInstance(hashAlgorithm);
        if (messageDigest.getDigestLength() == 0) {
            throw new IllegalArgumentException("Hash algorithm must be one that creates a hash with a fixed size");
        }
    }
    
    public RSASESSigner() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this("ECB", "PKCS1Padding", "SHA1");
    }

    protected byte[] hash(byte[] data) throws IOException {
        return messageDigest.digest(data);
    }

    public byte[] sign() throws SignatureException {
        if (state != RSASESSigner.SIGN) {
            throw new SignatureException("Need to call initSign before sign");
        }
        try {
            byte[] first = this.encrypt(buffer, privateKey);
            byte[] second = this.encrypt(first, publicKey);
            byte[] hash = this.hash(buffer);
            byte[] third = ArrayUtils.concat(second, hash);
            return this.encrypt(third, privateKey);
        } catch (Exception er) {
            throw new SignatureException(er.getMessage());
        }
    }

    @Override
    public byte[] verify() throws SignatureException {
        if (state != RSASESSigner.VERIFY) {
            throw new SignatureException("Need to call initVerify before verify");
        }
        try {
            int hashSize = messageDigest.getDigestLength();
            byte[] first = this.decrypt(buffer, publicKey);
            
            if (first.length < hashSize) {
                throw new SignatureException("Can't find the hash.");
            }
            byte[] bufferHash = new byte[hashSize];
            System.arraycopy(first, first.length - hashSize, bufferHash, 0, hashSize);

            byte[] remaining = new byte[first.length - hashSize];
            System.arraycopy(first, 0, remaining, 0, first.length - hashSize);
            
            byte[] second = this.decrypt(remaining, privateKey);
            byte[] plain = this.decrypt(second, publicKey);
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
