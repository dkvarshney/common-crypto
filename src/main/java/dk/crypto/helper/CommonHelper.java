package dk.crypto.helper;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public final class CommonHelper {
    
    public static List<String> foldString(String text, int size) {
        List<String> ret = new ArrayList<String>((text.length() + size - 1) / size);
        for (int start = 0; start < text.length(); start += size) {
            ret.add(text.substring(start, Math.min(text.length(), start + size)));
        }
        return ret;
    }
    
    public static Path writeToFile(String filename, byte[] dataToWrite) throws IOException {
        File outputFile = new File(filename);
        return Files.write(outputFile.toPath(), dataToWrite);
    }
    
    public static byte[] readFileAsBytes(String filename) throws Exception {
        return Files.readAllBytes(Paths.get(filename));
    }
}
