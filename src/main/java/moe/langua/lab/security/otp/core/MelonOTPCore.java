package moe.langua.lab.security.otp.core;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class MelonOTPCore {
    private final byte[] secretKey;

    public MelonOTPCore(byte[] secretKey) {
        this.secretKey = secretKey;
        truncate(0); //pre-load
    }

    private byte[] hMacSha256(byte[] contentByteArray, byte[] secretKeyByteArray) {
        SecretKey secretKey = new SecretKeySpec(secretKeyByteArray, "HmacSHA256");
        Mac mac = null;
        try {
            mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKey);
        } catch (NoSuchAlgorithmException | InvalidKeyException ignore) {
        }
        assert mac != null;
        return mac.doFinal(contentByteArray);
    }

    public long truncate(long offset) {
        byte[] otpRawData = hMacSha256(this.secretKey, Long.toBinaryString(Long.reverseBytes(offset)).getBytes());
        int tail = Byte.toUnsignedInt(otpRawData[31]);
        int otpOffset = (tail % 16) + ((tail >>> 4) % 8) + (tail >>> 7);
        long otpTruncated = 0;
        for (int offsetOffset = 0; offsetOffset < 8; offsetOffset++) {
            otpTruncated += (Byte.toUnsignedLong(otpRawData[otpOffset + offsetOffset]) << (offsetOffset * 8));
        }
        return otpTruncated;
    }
}
