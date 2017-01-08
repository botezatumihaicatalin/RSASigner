import java.security.PrivateKey;
import java.security.PublicKey;

import core.RSACertificateGenerator;
import core.RSAESESigner;

public class Main {

    public static void main(String[] args) {
        try {
            RSACertificateGenerator gen = new RSACertificateGenerator();

            // Alice wants to send a message to Bob.
            gen.generate();
            PublicKey alicePublic = gen.getPublicKey();
            PrivateKey alicePrivate = gen.getPrivateKey();

            gen.generate();
            PublicKey bobPublic = gen.getPublicKey();
            PrivateKey bobPrivate = gen.getPrivateKey();

            RSAESESigner signer = new RSAESESigner();
            signer.initSign(alicePrivate, bobPublic);
            signer.update("My name is what? My name is who? My name is...".getBytes());
            byte[] signed = signer.sign();

            signer.initVerify(bobPrivate, alicePublic);
            signer.update(signed);

            byte[] unsigned = signer.verify();
            System.out.println(new String(unsigned));
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

}
