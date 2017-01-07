import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import core.RSACertificateGenerator;

public class Main {

	public static void main(String[] args) {
		try {
			RSACertificateGenerator gen = new RSACertificateGenerator();
			gen.generateToDisk("C:\\Users\\botezatu\\Desktop\\Mihai", "Mihai-Botezatu");
			PublicKey pub1 = gen.getPublicKey();
			gen.loadFromDisk("C:\\Users\\botezatu\\Desktop\\Mihai", "Mihai-Botezatu");
			PublicKey pub2 = gen.getPublicKey();
			System.out.println("Done");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}

}
