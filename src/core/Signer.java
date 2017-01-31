package core;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

public abstract class Signer {

    protected static int SIGN          = 0;
    protected static int VERIFY        = 1;
    protected static int UNINITIALIZED = -1;
    protected int        state;

    protected PublicKey  publicKey;
    protected PrivateKey privateKey;
    protected byte[]     buffer;

    public Signer() {
        buffer = new byte[0];
        state = Signer.UNINITIALIZED;
    }

    public void update(byte[] data) {
        buffer = new byte[data.length];
        System.arraycopy(data, 0, buffer, 0, data.length);
    }

    public void update(String filePath) throws IOException {
        FileInputStream inputStream = new FileInputStream(filePath);
        byte[] buffer = new byte[inputStream.available()];
        inputStream.read(buffer);
        inputStream.close();
        this.update(buffer);
    }

    public void initSign(PrivateKey privateKey, PublicKey publicKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.state = Signer.SIGN;
    }

    public void initVerify(PrivateKey privateKey, PublicKey publicKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.state = Signer.VERIFY;
    }

    public abstract byte[] sign() throws SignatureException;

    public abstract boolean verify(byte[] signature)  throws SignatureException;
    
    public boolean verifyFile(String filePath) throws IOException, SignatureException {
        FileInputStream inputStream = new FileInputStream(filePath);
        byte[] buffer = new byte[inputStream.available()];
        inputStream.read(buffer);
        inputStream.close();
        return this.verify(buffer);
    }
    
    public void signToFile(String filePath) throws IOException, SignatureException {
        byte[] data = this.sign();
        FileOutputStream stream;
        stream = new FileOutputStream(filePath);
        stream.write(data);
        stream.close();
    }
}
