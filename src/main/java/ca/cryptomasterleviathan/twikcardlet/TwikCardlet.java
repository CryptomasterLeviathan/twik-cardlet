package ca.cryptomasterleviathan.twikcardlet;

import javacard.framework.*;
import javacard.security.MessageDigest;

public class TwikCardlet extends Applet
{
    private byte[] recieved;
    private static final short MAX_LENGTH = 256;

    // Profile includes secret key, master password, and pin
    private static final byte SET_PROFILE = (byte)0x20;
    private static final byte GENERATE_HASH = (byte)0x30;
    private static final byte GENERATE_PASSWORD = (byte)0x40; // NOT IMPLEMENTED
    private static final byte GET_INFO = (byte) 0x90; // TODO: REMOVE THIS!!!

    // Constants for HMAC algorithm
    private static final byte I_PAD = (byte)0x36;
    private static final byte O_PAD = (byte)0x5C;

    private byte[] pin;
    private byte[] secretKey;
    private byte[] masterPassword;

    private static void padXOR(byte[] result, byte[] key, byte pad) {
        // TODO: Check that the result array is 64 bytes long!
        for(short i=0; i<result.length; i++) {
            if(i < key.length) {
                result[i] = (byte)(0xFF & (key[i] ^ pad));
            } else {
                result[i] = 0x00;
            }
        }
    }

    protected TwikCardlet() {
        recieved = new byte[MAX_LENGTH];
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength){
        new TwikCardlet();
    }

    public void process(APDU apdu){
        byte buffer[] = apdu.getBuffer();

        switch(buffer[ISO7816.OFFSET_INS]) {
            case SET_PROFILE:
                //First bytes are the pin P1 is the master password length and P2 is the secret key offset.
                pin = new byte[4];
                Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, pin, (short)0, (short)4);

                masterPassword = new byte[buffer[ISO7816.OFFSET_P1]];
                Util.arrayCopyNonAtomic(buffer, (short)(ISO7816.OFFSET_CDATA + 4), masterPassword, (short)0, buffer[ISO7816.OFFSET_P1]);
                return;
            case GENERATE_HASH:
                byte[] test = {(byte)'M', (byte)'a', (byte)'t', (byte)'t'};
                byte[] result = new byte[20];
                MessageDigest digest = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
                digest.doFinal(test, (short)0, (short)4, result, (short)0);
                Util.arrayCopyNonAtomic(result, (short)0, buffer, (short)0, (short)20);
                apdu.setOutgoingAndSend((short)0, (short)20);
                return;
            case GET_INFO:
                Util.arrayCopyNonAtomic(pin, (short)0, masterPassword, (short)0, (short)masterPassword.length);
                apdu.setOutgoingAndSend((short)0, (short)masterPassword.length);
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }    
}
