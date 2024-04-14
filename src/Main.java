

import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.MGF1ParameterSpec;
import java.security.*;
import java.util.Random;


public class Main {

    private RSAPadding padding;

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {

        OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1",
                new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);

        var cek = getRandomKey("AES", 256);
        var rsaPadding = RSAPadding.getInstance(256,
                SecureRandom.getInstanceStrong(), spec);
        var oaepPadding = rsaPadding.pad(cek.getEncoded());
        rsaPadding.unpad(oaepPadding);
        System.out.println("Tamanho bloco: " + oaepPadding.length);
    }

    private static Key getRandomKey(String cipher, int keySize) {
        byte[] randomKeyBytes = new byte[keySize / 8];
        Random random = new Random();
        random.nextBytes(randomKeyBytes);
        return new SecretKeySpec(randomKeyBytes, cipher);
    }
}