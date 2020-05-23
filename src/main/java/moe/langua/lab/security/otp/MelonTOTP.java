package moe.langua.lab.security.otp;

import moe.langua.lab.security.otp.core.MelonOTPCore;

import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.atomic.AtomicInteger;

public class MelonTOTP {
    private static final AtomicInteger workerCounter = new AtomicInteger(0);

    private final MelonOTPCore CORE;
    private final String OTP_CONFIG;
    private final float VERSION = 1.2F;

    private final long truncateValue;
    private final long[] passNow = new long[3];
    private final long circle;
    private final long keyOffset;
    private long timeOffset;

    public MelonTOTP(byte[] secretKey, long truncateValue, long expirationTimeInMillSeconds) {
        if (expirationTimeInMillSeconds <= 0)
            throw new IllegalArgumentException("expirationTimeInMillSeconds must be a positive value.");

        this.keyOffset = secretKey.length;
        this.truncateValue = truncateValue;
        this.circle = expirationTimeInMillSeconds;
        CORE = new MelonOTPCore(secretKey);
        OTP_CONFIG = this.getClass().getName() + ",Version=" + VERSION + ",Truncate=0x" + Long.toHexString(truncateValue) + ",ExpirationTime=0x" + Long.toHexString(circle);

        long now = System.currentTimeMillis();
        timeOffset = (now / circle) * circle;
        reset(timeOffset);

        new Timer("MelonTOTP-Worker-" + workerCounter.getAndAdd(1), true).scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                reset(timeOffset += circle);
            }
        }, new Date(timeOffset + circle), circle);
    }


    private void reset(long offset) {
        synchronized (passNow) {
            for (int index = 0; index < 3; index++) {
                passNow[index] = ((CORE.truncate(offset + circle * (index - 1) + keyOffset) & 0x7FFFFFFFFFFFFFFFL) % truncateValue);
                // password must be a positive value
            }
        }
    }

    public long[] getPassArray() {
        synchronized (passNow) {
            return passNow.clone();
        }
    }

    public boolean verify(long pass) {
        synchronized (passNow) {
            for (int index = 0; index < 3; index++) {
                if (pass == passNow[index]) return true;
            }
            return false;
        }
    }

    public long getPassNow() {
        synchronized (passNow) {
            return passNow[1];
        }
    }

    public String getOTPConfig() {
        return OTP_CONFIG;
    }

    public float getVersion() {
        return VERSION;
    }

    public long nextUpdate() {
        return timeOffset + circle;
    }

    @Override
    public String toString() {
        return getOTPConfig();
    }
}
