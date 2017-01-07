package core;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSASigner implements Signer {
	
	private final Cipher cipher;
	private final PublicKey publicKey;
    private final PrivateKey privateKey;
	
	public RSASigner() throws NoSuchAlgorithmException, NoSuchPaddingException {
		cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");	
		
		KeyPairGenerator keysGenerator = KeyPairGenerator.getInstance("RSA");
        keysGenerator.initialize(1024);
         
        KeyPair keys = keysGenerator.generateKeyPair();
        publicKey = keys.getPublic();
        privateKey = keys.getPrivate();
	}
	 
	private void encrypt(InputStream iStream, OutputStream oStream, Key key) throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		cipher.init(Cipher.ENCRYPT_MODE, key);
        byte buffer[] = new byte[117];
        int readed;
         
        while ((readed = iStream.read(buffer)) != -1) {
            byte readedBlock[] = new byte[readed];
            System.arraycopy(buffer, 0, readedBlock, 0, readed);
            byte encryptedBlock[] = cipher.doFinal(readedBlock);
            oStream.write(encryptedBlock);
        }
	}
	
	private void decrypt(InputStream iStream, OutputStream oStream, Key key) throws IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeyException {
		cipher.init(Cipher.DECRYPT_MODE, key);
        byte buffer[] = new byte[128];
         
        while (iStream.read(buffer) != -1) {
            byte decryptedBlock[] = cipher.doFinal(buffer);
            oStream.write(decryptedBlock);
        }
	}

	@Override
	public void generateSignature(InputStream iStream, OutputStream oStream) {
		ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
		try {
			this.encrypt(iStream, byteOutputStream, publicKey);
		}
		catch(Exception er) {
			System.out.println(er.getMessage());
		}
	}

	@Override
	public void verifySignature(InputStream isStream, OutputStream oStream) {
		// TODO Auto-generated method stub
		
	}

}
