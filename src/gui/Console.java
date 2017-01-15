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
    
    private void sign() {
        System.out.println("Choose the method: ");
        System.out.println("1: Encrypt -> Sign -> Encrypt");
        System.out.println("2: Sign -> Encrypt -> Sign");
        int option = inputScanner.nextInt();
        try {
            if (option == 1) {
                this.sign(new RSAESESigner());
            }
            else if (option == 2) {
                this.sign(new RSASESSigner());
            }
            else {
                throw new Exception("Invalid option!");
            } 
        }
        catch (Exception ex) {
            System.out.println("Error: " + ex.getMessage());
        }   
    }
    
    private void verify() {
        System.out.println("Choose the method: ");
        System.out.println("1: Encrypt -> Sign -> Encrypt");
        System.out.println("2: Sign -> Encrypt -> Sign");
        int option = inputScanner.nextInt();
        try {
            if (option == 1) {
                this.verify(new RSAESESigner());
            }
            else if (option == 2) {
                this.verify(new RSASESSigner());
            }
            else {
                throw new Exception("Invalid option!");
            } 
        }
        catch (Exception ex) {
            System.out.println("Error: " + ex.getMessage());
        }
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
                    this.sign();
                }
                else if (option == 3) {
                    this.verify();
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
    
    private void sign(Signer signer) {
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
            
            System.out.println("Enter the path for the output signed file: ");
            String outputFilePath = inputScanner.next();
            
            signer.signToFile(outputFilePath);
            System.out.println("Finished signing the file!");
        }
        catch(Exception ex) {
            System.out.println("Error: " + ex.getMessage());
        }
    }
    
    private void verify(Signer signer) {
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
            
            System.out.println("Enter the path for the output verified file: ");
            String outputFilePath = inputScanner.next();
            
            signer.verifyToFile(outputFilePath);
            System.out.println("Finished verifying the file!");
        }
        catch(Exception ex) {
            System.out.println("Error: " + ex.getMessage());
        }
    }
}
