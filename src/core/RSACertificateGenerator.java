package core;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSACertificateGenerator {
	
	private PublicKey publicKey;
	private PrivateKey privateKey;
	private final KeyFactory keyFactory;
	private final KeyPairGenerator keyPairGenerator;

	public RSACertificateGenerator() throws NoSuchAlgorithmException {
		this.keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		this.keyFactory = KeyFactory.getInstance("RSA");
	}
	
	public void generate() throws NoSuchAlgorithmException {
        this.keyPairGenerator.initialize(1024);
        KeyPair kp = this.keyPairGenerator.genKeyPair();
        publicKey = kp.getPublic();
        privateKey = kp.getPrivate();
    }
	
	public void savePublicKeyToDisk(String folder, String name) throws IOException {
		Path publicKeyPath = Paths.get(folder, name + ".pub");
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey.getEncoded());
		FileOutputStream outputStream = new FileOutputStream(publicKeyPath.toString());
		outputStream.write(keySpec.getEncoded());
		outputStream.close();
	}
	
	public void savePrivateKeyToDisk(String folder, String name) throws IOException {
		Path privateKeyPath = Paths.get(folder, name + ".priv");
		PKCS8EncodedKeySpec  keySpec = new PKCS8EncodedKeySpec (privateKey.getEncoded());
		FileOutputStream outputStream = new FileOutputStream(privateKeyPath.toString());
		outputStream.write(keySpec.getEncoded());
		outputStream.close();
	}
	
	public void loadPublicKeyFromDisk(String folder, String name) throws IOException, InvalidKeySpecException {
		Path publicKeyPath = Paths.get(folder, name + ".pub");
		FileInputStream inputStream = new FileInputStream(publicKeyPath.toString());
		byte[] buffer = new byte[inputStream.available()];
		inputStream.read(buffer);
		inputStream.close();
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
		publicKey = this.keyFactory.generatePublic(keySpec);
	}
	
	public void loadPrivateKeyFromDisk(String folder, String name) throws IOException, InvalidKeySpecException {
		Path publicKeyPath = Paths.get(folder, name + ".priv");
		FileInputStream inputStream = new FileInputStream(publicKeyPath.toString());
		byte[] buffer = new byte[inputStream.available()];
		inputStream.read(buffer);
		inputStream.close();
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
		publicKey = this.keyFactory.generatePublic(keySpec);
	}
	
	public void saveToDisk(String folder, String name) throws IOException {
		this.savePublicKeyToDisk(folder, name);
		this.savePrivateKeyToDisk(folder, name);	
	}
	
	public void loadFromDisk(String folder, String name) throws InvalidKeySpecException, IOException {
		this.loadPrivateKeyFromDisk(folder, name);
		this.loadPublicKeyFromDisk(folder, name);
	}
	
	public PublicKey getPublicKey() {
		return publicKey;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}
}
