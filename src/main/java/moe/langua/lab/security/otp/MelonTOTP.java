package moe.langua.lab.security.otp;

import moe.langua.lab.security.otp.core.MelonOTPCore;

import java.util.Timer;
import java.util.TimerTask;

public class MelonTOTP {
    final MelonOTPCore core;
    final byte[] secretKey;
    final long truncateValue;
    final long[] passNow = new long[3];
    private long offset;

    public MelonTOTP(byte[] secretKey, long truncateValue, long expirationTimeInMillSeconds) {
        this.secretKey = secretKey;
        this.truncateValue = truncateValue;
        core = new MelonOTPCore(secretKey);
        long now = System.currentTimeMillis();
        offset = now / expirationTimeInMillSeconds;
        long initialDelay = (offset + 1) * expirationTimeInMillSeconds - now;
        reset(offset++);
        new Timer().schedule(new TimerTask() {
            @Override
            public void run() {
                new Timer().schedule(new TimerTask() {
                    @Override
                    public void run() {
                        reset(offset++);
                    }
                }, 0, expirationTimeInMillSeconds);

            }
        }, initialDelay);
    }


    private void reset(long offset) {
        synchronized (passNow) {
            for (int index = 0; index < 3; index++) {
                passNow[index] = core.truncate(offset - index - 1) % truncateValue;
                if (passNow[index] < 0) passNow[index] = -passNow[index];
            }
        }
    }

    public long[] getPassArray() {
        synchronized (passNow) {
            return passNow.clone();
        }
    }

    public boolean verify(long pass) {
        synchronized (passNow){
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

}
