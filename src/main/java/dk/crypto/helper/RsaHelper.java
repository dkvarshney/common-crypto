package dk.crypto.helper;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource.PSpecified;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.InvalidWrappingException;
import org.bouncycastle.crypto.KeyUnwrapper;
import org.bouncycastle.crypto.KeyWrapper;
import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.SymmetricSecretKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPublicKey;
import org.bouncycastle.crypto.fips.FipsAES;
import org.bouncycastle.crypto.fips.FipsKeyUnwrapperUsingSecureRandom;
import org.bouncycastle.crypto.fips.FipsKeyWrapperUsingSecureRandom;
import org.bouncycastle.crypto.fips.FipsRSA;
import org.bouncycastle.crypto.fips.FipsRSA.WrapParameters;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.pkcs.PKCSException;

public final class RsaHelper {

    public static KeyPair generateKeypair(int keysize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keysize);
        return keyGen.genKeyPair();
    }
    
    public static RSAPublicKey readRSAPublicKeyFromFile(String filename) throws Exception {
        String fileContents = new String(CommonHelper.readFileAsBytes(filename));
        String publicKeyPEM = fileContents.replaceAll("-----BEGIN PUBLIC KEY-----(\\n|\\r|\\r\\n)", "");
        publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");
        
        byte[] decoded = org.bouncycastle.util.encoders.Base64.decode(publicKeyPEM.trim());
        
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) kf.generatePublic(spec);
    }
    
    public static RSAPrivateKey readRSAPrivateKeyFromFile(String pathToPrivateKey) throws PKCSException, IOException {
        final File encryptedPrivateKeyFile = new File(pathToPrivateKey);
        final JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(new BouncyCastleFipsProvider());
        final PrivateKeyInfo keyInfo;
        try (InputStreamReader privateKeyReader = new InputStreamReader(new FileInputStream(encryptedPrivateKeyFile))) {
            PEMParser pemReader = new PEMParser(privateKeyReader);
            PEMKeyPair pemObject = (PEMKeyPair) pemReader.readObject();
            keyInfo = pemObject.getPrivateKeyInfo();
        }
        return (RSAPrivateKey) converter.getPrivateKey(keyInfo);
    }
    
    @SuppressWarnings({"unchecked", "rawtypes"})
    public static byte[] wrapWithRsaOaepAesSha256(RSAPublicKey wrappingKey, byte[] keyToWrap) {
        try {
            byte[] randomAESKey = AesHelper.generateAes(32 * 8).getEncoded();
            
            AsymmetricRSAPublicKey rsaPublicKey = new AsymmetricRSAPublicKey(FipsRSA.ALGORITHM, wrappingKey.getModulus(), wrappingKey.getPublicExponent());
            org.bouncycastle.crypto.fips.FipsRSA.WrapParameters wrapParameters = FipsRSA.WRAP_OAEP.withDigest(FipsSHS.Algorithm.SHA256);
            org.bouncycastle.crypto.fips.FipsRSA.KeyWrapOperatorFactory rsaAesEncrypter = new org.bouncycastle.crypto.fips.FipsRSA.KeyWrapOperatorFactory();
            
            FipsKeyWrapperUsingSecureRandom<WrapParameters> keyWrapper = (FipsKeyWrapperUsingSecureRandom)rsaAesEncrypter.createKeyWrapper(
                    rsaPublicKey, wrapParameters).withSecureRandom(SecureRandom.getInstanceStrong());
            byte[] wrappedAESKeyBytes = keyWrapper.wrap(randomAESKey, 0, randomAESKey.length);
            
            SymmetricKey aesWrappingKey = new SymmetricSecretKey(FipsAES.ALGORITHM, randomAESKey);
            org.bouncycastle.crypto.fips.FipsAES.KeyWrapOperatorFactory aesKeyOperatorFactory = new org.bouncycastle.crypto.fips.FipsAES.KeyWrapOperatorFactory();
            KeyWrapper<FipsAES.WrapParameters> wrapper = aesKeyOperatorFactory.createKeyWrapper(aesWrappingKey, FipsAES.KWP);
            byte[] wrappedKey = wrapper.wrap(keyToWrap, 0, keyToWrap.length);
            
            return org.bouncycastle.util.Arrays.concatenate(wrappedAESKeyBytes, wrappedKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    
    public static byte[] unwrapWithRsaOaepAesSha256(RSAPrivateKey unwrappingKey, byte[] wrappedMaterial, int keySize) throws Exception {
        // Split wrapped data in two parts such that:
        // The first part if the Wrapped temp AES Key (Size equal to the RSA KP Size)
        // The second part is the Wrapped target key.
        ByteBuffer byteBuffer = ByteBuffer.wrap(wrappedMaterial);
    
        byte[] wrappedTempAesKey = ByteBuffer.allocate(keySize).array();
        byteBuffer.get(wrappedTempAesKey);
    
        byte[] wrappedTargetKey = ByteBuffer.allocate(byteBuffer.remaining()).array();
        byteBuffer.get(wrappedTargetKey);
    
        // Unwrap the wrappedTempAES key using the Private Key
        byte[] tempAesKey = unwrapRsaOaepSha256Mgf1PaddedData(wrappedTempAesKey, unwrappingKey);
    
        // Unwrap the wrappedTargetkey using the tempAesKey
        return unwrapAesKey(wrappedTargetKey, tempAesKey);
    }
    
    public static byte[] unwrapWithRsaOaepSha256(RSAPrivateKey unwrappingKey, byte[] wrappedMaterial) throws Exception {
        AsymmetricRSAPrivateKey rsaPrivateKey =
                new AsymmetricRSAPrivateKey(FipsRSA.ALGORITHM, unwrappingKey.getModulus(), unwrappingKey.getPrivateExponent());
        FipsRSA.WrapParameters wrapParameters = FipsRSA.WRAP_OAEP.withDigest(FipsSHS.Algorithm.SHA256);
    
        FipsRSA.KeyWrapOperatorFactory wrapFact = new FipsRSA.KeyWrapOperatorFactory();
        FipsKeyUnwrapperUsingSecureRandom unwrapper = (FipsKeyUnwrapperUsingSecureRandom) wrapFact.createKeyUnwrapper(rsaPrivateKey, wrapParameters)
                .withSecureRandom(SecureRandom.getInstanceStrong());
    
        return unwrapper.unwrap(wrappedMaterial, 0, wrappedMaterial.length);
    }
    
    public static byte[] wrapWithRsaOaepSha256(RSAPublicKey wrappingKey, byte[] keyToWrap) throws Exception {
        MGF1ParameterSpec mgf1ParameterSpec = MGF1ParameterSpec.SHA256;
        String sha = mgf1ParameterSpec.getDigestAlgorithm();
        String oaepPaddingString = "RSA/None/OAEPWith" + sha + "AndMGF1Padding";
        Cipher cipher = Cipher.getInstance(oaepPaddingString, new BouncyCastleFipsProvider());
        OAEPParameterSpec oaepParameterSpec = new OAEPParameterSpec(sha, "MGF1", mgf1ParameterSpec, PSpecified.DEFAULT);
        cipher.init(3, wrappingKey, oaepParameterSpec);
        Key keyToEncrypt = new SecretKeySpec(keyToWrap, "AES");
        return cipher.wrap(keyToEncrypt);
    }
    
    static byte[] unwrapRsaOaepSha256Mgf1PaddedData(byte[] wrappedData, RSAPrivateKey privateKey) throws InvalidWrappingException, NoSuchAlgorithmException {
        AsymmetricRSAPrivateKey rsaPrivateKey =
                new AsymmetricRSAPrivateKey(FipsRSA.ALGORITHM, privateKey.getModulus(), privateKey.getPrivateExponent());
        FipsRSA.WrapParameters wrapParameters = FipsRSA.WRAP_OAEP.withDigest(FipsSHS.Algorithm.SHA256);
        
        FipsRSA.KeyWrapOperatorFactory wrapFact = new FipsRSA.KeyWrapOperatorFactory();
        FipsKeyUnwrapperUsingSecureRandom unwrapper = (FipsKeyUnwrapperUsingSecureRandom) wrapFact.createKeyUnwrapper(rsaPrivateKey, wrapParameters)
                .withSecureRandom(SecureRandom.getInstanceStrong());
        
        return unwrapper.unwrap(wrappedData, 0, wrappedData.length);
    }
    
    static byte[] unwrapAesKey(byte[] keyToUnWrap,byte[] unWrappingKey) throws Exception {
        FipsAES.KeyWrapOperatorFactory KEY_OPERATOR_FACTORY = new FipsAES.KeyWrapOperatorFactory();
        SymmetricKey aesKey = new SymmetricSecretKey(FipsAES.ALGORITHM, unWrappingKey);
        KeyUnwrapper<FipsAES.WrapParameters> wrapper = KEY_OPERATOR_FACTORY.createKeyUnwrapper(aesKey, FipsAES.KWP);
        return wrapper.unwrap(keyToUnWrap, 0, keyToUnWrap.length);
    }
    
    static PEMKeyPair decryptKeyPair(PEMEncryptedKeyPair encryptedKeyPair, String password) throws IOException {
        PEMDecryptorProvider pemDecryptorProvider = new JcePEMDecryptorProviderBuilder()
                .setProvider(new BouncyCastleFipsProvider()).build(password.toCharArray());
        return encryptedKeyPair.decryptKeyPair(pemDecryptorProvider);
    }
}
