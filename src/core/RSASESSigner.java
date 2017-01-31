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
    public boolean verify(byte[] signature) throws SignatureException {
        if (state != RSASESSigner.VERIFY) {
            throw new SignatureException("Need to call initVerify before verify");
        }
        try {
            int hashSize = messageDigest.getDigestLength();
            byte[] first = this.decrypt(signature, publicKey);
            
            if (first.length < hashSize) {
                return false;
            }
            
            byte[] bufferHash = this.hash(buffer);
            byte[] signatureHash = new byte[hashSize];
            System.arraycopy(first, first.length - hashSize, signatureHash, 0, hashSize);

            byte[] remaining = new byte[first.length - hashSize];
            System.arraycopy(first, 0, remaining, 0, first.length - hashSize);
            
            byte[] second = this.decrypt(remaining, privateKey);
            byte[] plain = this.decrypt(second, publicKey);
            
            // Check if the signatureHash and the buffer hash are equal.
            if (!MessageDigest.isEqual(bufferHash, signatureHash)) {
                return false;
            }
            
            // Check if the buffer is equal to the decrypted plain.
            if (!MessageDigest.isEqual(buffer, plain)) {
                return false;
            }
            
            return true;
        } catch (Exception er) {
            throw new SignatureException(er.getMessage());
        }
    }

}
