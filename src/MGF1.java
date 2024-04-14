
import java.security.*;

public class MGF1 {

    private final MessageDigest md;

    /**
     * Construct an instance of MGF1 based on the specified digest algorithm.
     */
    MGF1(String mdAlgo) throws NoSuchAlgorithmException {
        this.md = MessageDigest.getInstance(mdAlgo);
    }

    void generateAndXor(byte[] seed, int seedOfs, int seedLen, int maskLen,
                        byte[] out, int outOfs) throws RuntimeException {
        byte[] C = new byte[4]; // 32 bit counter
        byte[] digest = new byte[md.getDigestLength()];
        while (maskLen > 0) {
            md.update(seed, seedOfs, seedLen);
            md.update(C);
            try {
                md.digest(digest, 0, digest.length);
            } catch (DigestException e) {
                // should never happen
                throw new RuntimeException(e.toString());
            }
            for (int i = 0; (i < digest.length) && (maskLen > 0); maskLen--) {
                out[outOfs++] ^= digest[i++];
            }
            if (maskLen > 0) {
                // increment counter
                for (int i = C.length - 1; (++C[i] == 0) && (i > 0); i--) {
                    // empty
                }
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
