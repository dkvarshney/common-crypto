package dk.crypto.cli.command;

import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(name = "crypto", subcommands = {RSACommand.class, AESCommand.class})
public class CryptoCommand implements Callable<Integer> {
    
    @Override
    public Integer call() {
        return 0;
    }
    
    public static void main(String[] args) {
        int exitCode = new CommandLine(new CryptoCommand()).execute(args);
        System.exit(exitCode);
    }
}
