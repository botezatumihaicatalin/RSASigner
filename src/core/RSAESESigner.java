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
    
    @Override
    public boolean verify(byte[] signature) throws SignatureException {
        if (state != RSAESESigner.VERIFY) {
            throw new SignatureException("Need to call initVerify before verify");
        }
        try {
            int hashSize = messageDigest.getDigestLength();
            byte[] first = this.decrypt(signature, privateKey);
            byte[] second = this.decrypt(first, publicKey);
            if (second.length < 20) {
                return false;
            }
            
            byte[] signatureHash = new byte[hashSize];
            byte[] bufferHash = this.hash(buffer);
            
            System.arraycopy(second, second.length - hashSize, signatureHash, 0, hashSize);

            byte[] remaining = new byte[second.length - hashSize];
            System.arraycopy(second, 0, remaining, 0, second.length - hashSize);

            byte[] plain = this.decrypt(remaining, this.privateKey);
            
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
