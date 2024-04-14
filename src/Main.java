

import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.MGF1ParameterSpec;
import java.security.*;


public class Main {

    private RSAPadding padding;

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {

        OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1",
                new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);

        var rsaPadding = RSAPadding.getInstance(256,
                SecureRandom.getInstanceStrong(), spec);
        var oaepPadding = rsaPadding.pad("teste".getBytes(StandardCharsets.UTF_8));
        rsaPadding.unpad(oaepPadding);
        System.out.println("Tamanho bloco: " + oaepPadding.length);
    }
}