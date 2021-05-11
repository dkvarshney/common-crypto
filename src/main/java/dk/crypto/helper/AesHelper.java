package dk.crypto.helper;

import java.security.GeneralSecurityException;
import java.security.Key;
import javax.crypto.KeyGenerator;

public final class AesHelper {
    
    public static Key generateAes(int size) throws GeneralSecurityException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(size);
        return keyGen.generateKey();
    }
}
