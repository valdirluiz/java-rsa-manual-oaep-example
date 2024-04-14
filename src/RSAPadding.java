
import javax.crypto.BadPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.*;
import java.security.spec.*;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public final class RSAPadding {

    private final int paddedSize;

    private SecureRandom random;

    private final int maxDataSize;

    private MessageDigest md;

    private MGF1 mgf;

    private byte[] lHash;

    public static RSAPadding getInstance(int paddedSize,
                                         SecureRandom random, OAEPParameterSpec spec)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        return new RSAPadding(paddedSize, random, spec);
    }

    private RSAPadding(int paddedSize, SecureRandom random,
                       OAEPParameterSpec spec) throws InvalidKeyException {
        this.paddedSize = paddedSize;
        this.random = random;
        String mdName = "SHA-1";
        String mgfMdName = mdName;
        byte[] digestInput = null;
        try {
                mdName = spec.getDigestAlgorithm();
                mgfMdName = ((MGF1ParameterSpec)spec.getMGFParameters())
                        .getDigestAlgorithm();
                PSource pSrc = spec.getPSource();
                digestInput = ((PSource.PSpecified) pSrc).getValue();
            md = MessageDigest.getInstance(mdName);
            mgf = new MGF1(mgfMdName);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidKeyException("Digest not available", e);
        }
        lHash = getInitialHash(md, digestInput);
        int digestLen = lHash.length;
        maxDataSize = paddedSize - 2 - 2 * digestLen;
        if (maxDataSize <= 0) {
            throw new InvalidKeyException
                    ("Key is too short for encryption using OAEPPadding" +
                            " with " + mdName + " and " + mgf.getName());

        }
    }

    private static final Map<String,byte[]> emptyHashes =
            Collections.synchronizedMap(new HashMap<String,byte[]>());

    private static byte[] getInitialHash(MessageDigest md,
                                         byte[] digestInput) {
        byte[] result;
        if ((digestInput == null) || (digestInput.length == 0)) {
            String digestName = md.getAlgorithm();
            result = emptyHashes.get(digestName);
            if (result == null) {
                result = md.digest();
                emptyHashes.put(digestName, result);
            }
        } else {
            result = md.digest(digestInput);
        }
        return result;
    }



    public byte[] pad(byte[] data) throws BadPaddingException {
        if (data.length > maxDataSize) {
            throw new BadPaddingException("Data must be shorter than "
                    + (maxDataSize + 1) + " bytes but received "
                    + data.length + " bytes.");
        }
        return padOAEP(data);
    }

    /**
     * Unpad the padded block and return the data.
     */
    public byte[] unpad(byte[] padded) throws BadPaddingException {
        return unpadOAEP(padded);
    }



    private byte[] padOAEP(byte[] data) {
        int hashLen = lHash.length;

        // 2.d: generate a random octet string seed of length hashLen
        // if necessary
        byte[] seed = new byte[hashLen];
        random.nextBytes(seed);

        // buffer for encoded message encodedMessage
        byte[] encodedMessage = new byte[paddedSize];

        // start and length of seed (as index into encodedMessage)
        int seedStart = 1;
        int seedLen = hashLen;

        // copy seed into encodedMessage
        System.arraycopy(seed, 0, encodedMessage, seedStart, seedLen);

        // start and length of data block DB in encodedMessage
        // we place it inside of encodedMessage to reduce copying
        int dbStart = hashLen + 1;
        int dbLen = encodedMessage.length - dbStart;

        // start of message M in encodedMessage
        int mStart = paddedSize - data.length;

        // build DB
        // 2.b: Concatenate lHash, PS, a single octet with hexadecimal value
        // 0x01, and the message M to form a data block DB of length
        // k - hashLen -1 octets as DB = lHash || PS || 0x01 || M
        // (note that PS is all zeros)
        System.arraycopy(lHash, 0, encodedMessage, dbStart, hashLen);
        encodedMessage[mStart - 1] = 1;
        System.arraycopy(data, 0, encodedMessage, mStart, data.length);

        // produce maskedDB
        mgf.generateAndXor(encodedMessage, seedStart, seedLen, dbLen, encodedMessage, dbStart);

        // produce maskSeed
        mgf.generateAndXor(encodedMessage, dbStart, dbLen, seedLen, encodedMessage, seedStart);

        return encodedMessage;
    }


    private byte[] unpadOAEP(byte[] padded) throws BadPaddingException {
        byte[] EM = padded;
        boolean bp = false;
        int hLen = lHash.length;

        if (EM[0] != 0) {
            bp = true;
        }

        int seedStart = 1;
        int seedLen = hLen;

        int dbStart = hLen + 1;
        int dbLen = EM.length - dbStart;

        mgf.generateAndXor(EM, dbStart, dbLen, seedLen, EM, seedStart);
        mgf.generateAndXor(EM, seedStart, seedLen, dbLen, EM, dbStart);

        // verify lHash == lHash'
        for (int i = 0; i < hLen; i++) {
            if (lHash[i] != EM[dbStart + i]) {
                bp = true;
            }
        }

        int padStart = dbStart + hLen;
        int onePos = -1;

        for (int i = padStart; i < EM.length; i++) {
            int value = EM[i];
            if (onePos == -1) {
                if (value == 0x00) {
                    // continue;
                } else if (value == 0x01) {
                    onePos = i;
                } else {  // Anything other than {0,1} is bad.
                    bp = true;
                }
            }
        }

        // We either ran off the rails or found something other than 0/1.
        if (onePos == -1) {
            bp = true;
            onePos = EM.length - 1;  // Don't inadvertently return any data.
        }

        int mStart = onePos + 1;

        // copy useless padding array for a constant-time method
        byte [] tmp = new byte[mStart - padStart];
        System.arraycopy(EM, padStart, tmp, 0, tmp.length);

        byte [] m = new byte[EM.length - mStart];
        System.arraycopy(EM, mStart, m, 0, m.length);

        BadPaddingException bpe = new BadPaddingException("Decryption error");

        if (bp) {
            throw bpe;
        } else {
            return m;
        }
    }


}
