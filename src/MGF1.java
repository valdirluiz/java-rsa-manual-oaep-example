
import java.security.*;

public class MGF1 {

    private final MessageDigest md;

    MGF1(String mdAlgo) throws NoSuchAlgorithmException {
        this.md = MessageDigest.getInstance(mdAlgo);
    }

    public void generateAndXor(byte[] seed, int seedOfs, int seedLen, int maskLen,
                               byte[] out, int outOfs) {
        byte[] counter = new byte[4];
        byte[] digest;

        while (maskLen > 0) {
            updateMessageDigest(seed, seedOfs, seedLen, counter);
            digest = calculateDigest();

            for (int i = 0; i < digest.length && maskLen > 0; i++) {
                out[outOfs++] ^= digest[i];
                maskLen--;
            }

            if (maskLen > 0) {
                incrementCounter(counter);
            }
        }
    }

    private void updateMessageDigest(byte[] seed, int seedOfs, int seedLen, byte[] counter) {
        md.update(seed, seedOfs, seedLen);
        md.update(counter);
    }

    private byte[] calculateDigest() {
        return md.digest();
    }

    private void incrementCounter(byte[] counter) {
        for (int i = counter.length - 1; i >= 0; i--) {
            if (++counter[i] != 0) {
                break;
            }
        }
    }


    /**
     * Returns the name of this MGF1 instance, i.e. "MGF1" followed by the
     * digest algorithm it based on.
     */
    String getName() {
        return "MGF1" + md.getAlgorithm();
    }
}
