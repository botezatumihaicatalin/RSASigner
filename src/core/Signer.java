package core;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

public interface Signer {
	
	public abstract void generateSignature(InputStream iStream, OutputStream oStream);
	public abstract void verifySignature(InputStream isStream, OutputStream oStream);
	
	public default void generateSignature(String inputPath, String outputPath) throws FileNotFoundException {
		FileInputStream inputStream = new FileInputStream(inputPath);
        FileOutputStream outputStream = new FileOutputStream(outputPath);
        this.generateSignature(inputStream, outputStream);
	}
	
	public default void verifySignature(String inputPath, String outputPath) throws FileNotFoundException {
		FileInputStream inputStream = new FileInputStream(inputPath);
        FileOutputStream outputStream = new FileOutputStream(outputPath);
        this.verifySignature(inputStream, outputStream);
	}
}
