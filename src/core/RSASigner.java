package core;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSASigner extends Signer {
	
	private final Cipher rsaCipher;
	private final MessageDigest sha1Digest;
	
	public RSASigner() throws NoSuchAlgorithmException, NoSuchPaddingException {
		super();
		this.rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		this.sha1Digest = MessageDigest.getInstance("SHA1");
	}
	
	private byte[] encrypt(byte[] data, Key key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
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
	
	private byte[] decrypt(byte[] data, Key key) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
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
	
	private byte[] hash(byte[] data) throws IOException {
		return this.sha1Digest.digest(data);
	}
	
 	public byte[] sign() throws SignatureException {
 		if (state != RSASigner.SIGN) {
 			throw new SignatureException("Need to call initSign before sign");
 		}
		try {
			byte[] first = this.encrypt(buffer, publicKey);
			byte[] hash = this.hash(buffer);
			byte[] second = ArrayUtils.concat(first, hash);
			byte[] third = this.encrypt(second, privateKey);
			return this.encrypt(third, publicKey);
  		}
		catch(Exception er) {
			throw new SignatureException(er.getMessage());
		}
	}
 	
 	public byte[] verify() throws SignatureException {
 		if (state != RSASigner.VERIFY) {
 			throw new SignatureException("Need to call initVerify before verify");
 		}
 		try {
 			byte[] first = this.decrypt(buffer, privateKey);
 			byte[] second = this.decrypt(first, publicKey);
 			if (second.length < 20) {
 				throw new SignatureException("Can't find the hash.");
 			}
 			byte[] bufferHash = new byte[20];
 			System.arraycopy(second, second.length - 20, bufferHash, 0, 20);
 			
 			byte[] remaining = new byte[second.length - 20];
 			System.arraycopy(second, 0, remaining, 0, second.length - 20);
 			
 			byte[] plain = this.decrypt(remaining, this.privateKey);
 			byte[] plainHash = this.hash(plain);
 			if (!MessageDigest.isEqual(bufferHash, plainHash)) {
 				throw new SignatureException("Hashes don't match.");
 			}
 			return plain;
 			
 		}
 		catch(Exception er) {
 			throw new SignatureException(er.getMessage());
 		}
 	}
}
