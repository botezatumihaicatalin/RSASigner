package gui;

import java.util.Scanner;

import core.RSACertificateGenerator;
import core.RSAESESigner;
import core.RSASESSigner;
import core.Signer;

public final class Console {
    
    Scanner inputScanner;
    
    public Console() {
        inputScanner = new Scanner(System.in); 
    }
    
    private void generate() {
        System.out.println("Enter the path for the private key: ");
        String privateKeyPath = inputScanner.next();
        System.out.println("Enter the path for the public key: ");
        String publicKeyPath = inputScanner.next();
        System.out.println("Generating the public/private key pair...");
        try {
            RSACertificateGenerator certGenerator = new RSACertificateGenerator();
            certGenerator.generate();
            certGenerator.savePrivateKeyToDisk(privateKeyPath);
            certGenerator.savePublicKeyToDisk(publicKeyPath);
            System.out.println("Succesfully generated the public/private key pair!");
        }
        catch(Exception ex) {
            System.out.println("Error: " + ex.getMessage());
        }
    }
    
    private Signer chooseSignature() {
        System.out.println("Choose the method: ");
        System.out.println("1: Encrypt -> Sign -> Encrypt");
        System.out.println("2: Sign -> Encrypt -> Sign");
        System.out.println("3: Cancel");
        int option = inputScanner.nextInt();
        try {
            if (option == 1) {
                return new RSAESESigner();
            }
            else if (option == 2) {
                return new RSASESSigner();
            }
            else if (option == 3) {
                return null;
            }
            else {
                throw new Exception("Invalid option!");
            } 
        }
        catch (Exception ex) {
            System.out.println("Error: " + ex.getMessage());
        }
        
        return null;
    }
    
    public void start() {
        boolean running = true;
        
        while (running) {
            System.out.println("Choose an option: ");
            System.out.println("1: Generate certificate");
            System.out.println("2: Sign a file");
            System.out.println("3: Verify a file");
            System.out.println("4: Exit");
            int option = inputScanner.nextInt();
            try {
                if (option == 1) {
                    this.generate();
                }
                else if (option == 2) {
                    this.signFile(this.chooseSignature());
                }
                else if (option == 3) {
                    this.verifyFile(this.chooseSignature());
                }
                else if (option == 4) {
                    running = false;
                }
                else {
                    throw new Exception("Invalid option!");
                } 
            }
            catch (Exception ex) {
                System.out.println("Error: " + ex.getMessage());
            }
            System.out.println("");
        }
    }
    
    private void signFile(Signer signer) {
        if (signer == null) {
            return;
        }
        try {
            RSACertificateGenerator certGenerator = new RSACertificateGenerator();
            
            System.out.println("Enter the path for the private key: ");
            String privateKeyPath = inputScanner.next();
            certGenerator.loadPrivateKeyFromDisk(privateKeyPath);
            System.out.println("Enter the path for the public key: ");
            String publicKeyPath = inputScanner.next();
            certGenerator.loadPublicKeyFromDisk(publicKeyPath);
            
            signer.initSign(certGenerator.getPrivateKey(), certGenerator.getPublicKey());
            
            System.out.println("Enter the path for the file to be signed: ");
            String inputFilePath = inputScanner.next();
            signer.update(inputFilePath);
            
            System.out.println("Enter the path for the signature file: ");
            String signatureFilePath = inputScanner.next();
            
            signer.signToFile(signatureFilePath);
            System.out.println("Finished signing the file!");
        }
        catch(Exception ex) {
            System.out.println("Error: " + ex.getMessage());
        }
    }
    
    private void verifyFile(Signer signer) {
        if (signer == null) {
            return;
        }
        try {
            RSACertificateGenerator certGenerator = new RSACertificateGenerator();
            
            System.out.println("Enter the path for the private key: ");
            String privateKeyPath = inputScanner.next();
            certGenerator.loadPrivateKeyFromDisk(privateKeyPath);
            System.out.println("Enter the path for the public key: ");
            String publicKeyPath = inputScanner.next();
            certGenerator.loadPublicKeyFromDisk(publicKeyPath);
            
            signer.initVerify(certGenerator.getPrivateKey(), certGenerator.getPublicKey());
            
            System.out.println("Enter the path for the file to be verified: ");
            String inputFilePath = inputScanner.next();
            signer.update(inputFilePath);
            
            System.out.println("Enter the path for the signature file: ");
            String signatureFilePath = inputScanner.next();
            
            boolean isValid = signer.verifyFile(signatureFilePath);
            if (isValid) {
                System.out.println("The signature for the provided file is valid!");
            }
            else {
                System.out.println("The signature for the provided file is invalid!");
            }
        }
        catch(Exception ex) {
            System.out.println("Error: " + ex.getMessage());
        }
    }
}
