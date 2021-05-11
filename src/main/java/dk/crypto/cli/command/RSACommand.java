package dk.crypto.cli.command;

import dk.crypto.helper.CommonHelper;
import dk.crypto.helper.RsaHelper;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "rsa", description = "RSA commands")
public class RSACommand implements Callable<Integer> {
    
    public enum WrapAlgorithm {
        RSA_OAEP_SHA256,
        RSA_OAEP_AES_SHA256
    }
    
    @Override
    public Integer call() {
        System.err.println("Supported Commands: wrap, unwrap, generate");
        return 1;
    }
    
    
    @Command(name = "wrap", description = "Wrap the material")
    public void rsaWrap(
            @Option(names = {"-wrappingkey", "--wrapping-key"}, required = true, description = "Public key (PEM) to wrap the material") File wrappingKeyFile,
            @Option(names = {"-material", "--material-file"}, required = true, description = "Material file to be wrapped") File materialFile,
            @Option(names = {"-wrapalgo", "--wrap-algorithm"}, required = true, description = "Algorithm to wrap the material") WrapAlgorithm wrapAlgorithm,
            @Option(names = {"-output", "--output-file"}, required = true, description = "Output file to write wrapped material") File outputFile) throws Exception {
    
        RSAPublicKey wrappingKey = RsaHelper.readRSAPublicKeyFromFile(wrappingKeyFile.getAbsolutePath());
        byte[] materialToWrap = CommonHelper.readFileAsBytes(materialFile.getAbsolutePath());
    
        byte[] wrappedMaterial = null;
        if (wrapAlgorithm.equals(WrapAlgorithm.RSA_OAEP_AES_SHA256)) {
            wrappedMaterial = RsaHelper.wrapWithRsaOaepAesSha256(wrappingKey, materialToWrap);
        } else if (wrapAlgorithm.equals(WrapAlgorithm.RSA_OAEP_SHA256)) {
            wrappedMaterial = RsaHelper.wrapWithRsaOaepSha256(wrappingKey, materialToWrap);
        } else {
            throw new RuntimeException("Unsupported WrapAlgorithm: " + wrapAlgorithm);
        }
        
        System.out.println("Writing wrapped material to file: " + outputFile.getAbsolutePath());
        CommonHelper.writeToFile(outputFile.getAbsolutePath(), wrappedMaterial);
        System.out.println("Successfully wrapped the material.");
    }
    
    @Command(name = "unwrap", description = "Perform RSA unwrap")
    public void rsaUnwrap(@Option(names = {"-unwrappingkey", "--unwrapping-key"}, required = true, description = "Private key (PEM) to un-wrap the material") File unwrappingKeyFile,
            @Option(names = {"-material", "--material-file"}, required = true, description = "Wrapped material to be un-wrapped") File materialFile,
            @Option(names = {"-wrapalgo", "--wrap-algorithm"}, required = true, description = "Algorithm to wrap the material") WrapAlgorithm wrapAlgorithm,
            @Option(names = {"-output", "--output-file"}, required = true, description = "Output file to write un-wrapped material") File outputFile) throws Exception {
        RSAPrivateKey privateKey = RsaHelper.readRSAPrivateKeyFromFile(unwrappingKeyFile.getAbsolutePath());
        byte[] materialToUnwrap = CommonHelper.readFileAsBytes(materialFile.getAbsolutePath());
        byte[] unwrappedMaterial = null;
        if (wrapAlgorithm.equals(WrapAlgorithm.RSA_OAEP_AES_SHA256)) {
            int keysize = privateKey.getModulus().bitLength() / 8;
            unwrappedMaterial = RsaHelper.unwrapWithRsaOaepAesSha256(privateKey, materialToUnwrap, keysize);
        } else if (wrapAlgorithm.equals(WrapAlgorithm.RSA_OAEP_SHA256)) {
            unwrappedMaterial = RsaHelper.unwrapWithRsaOaepSha256(privateKey, materialToUnwrap);
        } else {
            throw new RuntimeException("Unsupported WrapAlgorithm: " + wrapAlgorithm);
        }
    
        System.out.println("Writing un-wrapped material to file: " + outputFile.getAbsolutePath());
        CommonHelper.writeToFile(outputFile.getAbsolutePath(), unwrappedMaterial);
        System.out.println("Successfully un-wrapped the material.");
    }
    
    @Command(name = "generate", description = "Generate a RSA keypair")
    void generateKeyPair(
            @Option(names = {"-keysize", "--key-size"}, required = true, description = "The keysize of keypair") int keysize,
            @Option(names = {"-privatekey", "--private-key"}, required = true, description = "Output file to write the private key") File privateKey,
            @Option(names = {"-publickey", "--public-key"}, required = true, description = "Output file to write the public key") File publicKey) throws Exception {
        KeyPair keyPair = RsaHelper.generateKeypair(keysize);
        
        String base64PrivateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        String foldPrivateKey = String.join("\n", CommonHelper.foldString(base64PrivateKey, 64));
        String encodedPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n" + foldPrivateKey + "\n-----END RSA PRIVATE KEY-----\n";
        
        String base64PublicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        String foldPublicKey = String.join("\n", CommonHelper.foldString(base64PublicKey, 64));
        String encodedPublicKey = "-----BEGIN PUBLIC KEY-----\n" + foldPublicKey + "\n-----END PUBLIC KEY-----\n";
        
        System.out.println("Writing private key to: " + privateKey.getAbsolutePath());
        Files.write(privateKey.toPath(), encodedPrivateKey.getBytes(StandardCharsets.UTF_8));
    
        System.out.println("Writing public key to: " + publicKey.getAbsolutePath());
        Files.write(publicKey.toPath(), encodedPublicKey.getBytes(StandardCharsets.UTF_8));
        
        System.out.println("Successfully generate RSA keypair.");
    }
}
