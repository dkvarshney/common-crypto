package dk.crypto.cli.command;

import dk.crypto.helper.AesHelper;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.Key;
import java.util.Base64;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "aes", description = "AES commands")
public class AESCommand  implements Callable<Integer> {
    
    @Override
    public Integer call() {
        System.err.println("Supported Commands: generate");
        return 1;
    }
    
    @Command(name = "generate", description = "Generate a AES key")
    void generateKeyPair(
            @Option(names = {"-keysize", "--key-size"}, required = true, description = "The keysize of keypair") int keysize,
            @Option(names = {"-base64", "--base64-encode"}, required = false, description = "Should the key be base64 encoded") boolean base64Encode,
            @Option(names = {"-output", "--output-file"}, required = true, description = "File to write the private key") File outputFile) throws Exception {
        Key key = AesHelper.generateAes(keysize);
        
        if (base64Encode) {
            System.out.println("Writing base64 encoded key to: " + outputFile.getAbsolutePath());
            String base64Key = Base64.getEncoder().encodeToString(key.getEncoded());
            Files.write(outputFile.toPath(), base64Key.getBytes(StandardCharsets.UTF_8));
        } else {
            System.out.println("Writing key to: " + outputFile.getAbsolutePath());
            Files.write(outputFile.toPath(), key.getEncoded());
        }
        System.out.println("Successfully generate AES key.");
    }
}
