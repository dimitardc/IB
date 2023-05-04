import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

class AES {

    public static KeyGenerator key;
    public static SecretKeySpec keySpec;

    static {
        try {
            key = KeyGenerator.getInstance("AES");
            SecureRandom random = new SecureRandom();
            key.init(random);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static Key secretKey = key.generateKey();


    public static byte[] encrypt(byte[] strToEncrypt) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.update(strToEncrypt);
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }
}

class ClearTextFrame {
    public static String FullFrame;
    public static String FrameHeader;
    public static String FrameData;
    public static int pn;
    int headerCount;
    int dataCount;

    public ClearTextFrame() {
        FrameHeader = "";
        FrameData = "";
    }

    public void generateFrame() {
        headerCount = getRandomNumber(32, 70);                   //32,70
        dataCount = getRandomNumber(160, 300);                   //300,500
        FrameHeader = FrameBuilder(headerCount);
        FrameData = FrameBuilder(dataCount);
        Random r = new Random();
        pn = r.nextInt(1000);
        FullFrame = FrameHeader + "" + pn + "" + FrameData;
    }

    public String FrameBuilder(int n) {              //rnd alhpanumeric frame
        String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789" + "abcdefghijklmnopqrstuvxyz";
        StringBuilder sb = new StringBuilder(n);

        for (int i = 0; i < n; i++) {
            int index = (int) (AlphaNumericString.length() * Math.random());
            sb.append(AlphaNumericString.charAt(index));
        }

        return sb.toString();
    }

    public int getRandomNumber(int min, int max) {
        return (int) ((Math.random() * (max - min)) + min);
    }

    String getHeader() {
        return FrameHeader;
    }

    String getFrameData() {
        return FrameData;
    }
}

class EncryptedFarme {
    public String data;
    public String header;
    public int pn;
    public Integer Ctr;
    public byte[] CTRbytes;
    public String encDataString;
    public byte[] encDataBytes;
    public byte[] EncryptedMIC;
    public byte[] CTRBytesBeforeIncrement;
    public ArrayList<byte[]> lista;

    public EncryptedFarme(Integer Ctr, byte[] CTRbytes) {
        this.Ctr = Ctr;                                          //Ctr veke pocetno inkriptiran
        encDataString = "";                                 //toa shto ke go kriptirame i pratime
        header = ClearTextFrame.FrameHeader;                //ne se kriptira
        encDataBytes = new byte[16];
        this.CTRbytes = CTRbytes;
        pn = ClearTextFrame.pn;
        EncryptedMIC = new byte[8];
        CTRBytesBeforeIncrement = new byte[16];
    }

    public ArrayList<byte[]> getLista() {
        return lista;
    }

    public void sendEncrypted() {
        data = TestAES.DATA;
        CTRBytesBeforeIncrement = CTRbytes;
        int len = data.length() / 16;
        int borderLeft = 0;
        int borderRight = 16;
        String CTRString;
        lista = new ArrayList<>();
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < len; i++) {             //kriptiranje na DATA so CTR
            Ctr++;
            CTRString = Ctr.toString();
            for (int j = CTRString.length(); j < 16; j++) {
                CTRString += "0";
            }
            CTRbytes = AES.encrypt(CTRString.getBytes(StandardCharsets.UTF_8));
            byte[] DataTemp = data.substring(borderLeft, borderRight).getBytes(StandardCharsets.UTF_8);
            for (int j = 0; j < DataTemp.length; j++) {
                encDataBytes[j] = (byte) (CTRbytes[j] ^ DataTemp[j]);
            }
            lista.add(encDataBytes);
            encDataString += new String(encDataBytes);
            for(byte b : encDataBytes){
                sb.append(String.format("%02X ", b));
            }
            borderLeft += 16;
            borderRight += 16;
        }


        System.out.println("-------FRAME-------");
        System.out.println("Header " + header);
        System.out.println("PN: " + pn);
        System.out.println("Encrypcted data: ");
        System.out.println(encDataString);
        System.out.println("Encrypted data but in HEX: ");
        System.out.println(sb);
        System.out.println("-------------------");
    }
}

public class TestAES {


    public static String HEADER;                                            //SO 0 PADDED
    public static String DATA;                                              //SO 0 PADDED
    public static int first = 1;

    static byte[] MICalc(byte[] IV, String header1, byte[] CTRbytes, String data) {

        byte[] xor = new byte[16];                                      //toa shto ke se vlece
        int j1 = header1.length() % 16;                                 //kolku imame vo posleden blok
        int j2 = data.length() % 16;                                   //kolku imame vo posleden blok
        byte[] FinalMic = new byte[8];
        StringBuilder es = new StringBuilder();
        if (j1 != 0) {
            HEADER = addPadding(header1, j1);
        } else {
            HEADER = header1;
        }
        if (j2 != 0) {
            DATA = addPadding(data, j2);
        } else {
            DATA = data;
        }

        if (first == 1) {
            System.out.println("HEADER: " + HEADER);
            System.out.println("DATA: " + DATA);
            first = 0;
        }
        int n1 = HEADER.length() / 16;                //kolku blokovi vo header
        int n2 = DATA.length() / 16;                  //bloka vo data

        int borderLeft = 0;
        int borderRight = 16;

        for (int i = 0; i < 1; i++) {                 //first block and key
            byte[] HeaderTemp = HEADER.substring(borderLeft, borderRight).getBytes(StandardCharsets.UTF_8);
            for (int j = 0; j < HeaderTemp.length; j++) {
                xor[j] = (byte) (HeaderTemp[j] ^ IV[j]);
            }
        }

        xor = AES.encrypt(xor);

        borderLeft += 16;
        borderRight += 16;
        for (int i = 0; i < n1 - 1; i++) {             //rest of header
            byte[] HeaderTemp = HEADER.substring(borderLeft, borderRight).getBytes(StandardCharsets.UTF_8);
            for (int j = 0; j < HeaderTemp.length; j++) {
                xor[j] = (byte) (xor[j] ^ HeaderTemp[j]);
            }
            xor = AES.encrypt(xor);
            borderLeft += 16;
            borderRight += 16;
        }

        borderLeft = 0;
        borderRight = 16;
        for (int i = 0; i < n2; i++) {             //all data
            byte[] DataTemp = DATA.substring(borderLeft, borderRight).getBytes(StandardCharsets.UTF_8);
            for (int j = 0; j < DataTemp.length; j++) {
                xor[j] = (byte) (xor[j] ^ DataTemp[j]);
            }
            xor = AES.encrypt(xor);
            borderLeft += 16;
            borderRight += 16;
        }
        for (int i = 0; i < 8; i++) {
            FinalMic[i] = (byte) (xor[i] ^ CTRbytes[i]);
        }

        return FinalMic;
    }

    private static String addPadding(String info, int amountInLast) {
        for (int i = amountInLast; i < 16; i++) {
            info += "0";
        }
        return info;
    }


    private static String decryptDATA(Integer ctr, ArrayList<byte[]> lista) {

        Integer Counter = ctr;
        String data = TestAES.DATA;
        int len = data.length() / 16;
        int borderLeft = 0, borderRight = 16;
        String CTRString = "";
        byte[] decDataBytes = new byte[16];
        byte[] CTRbytes = new byte[16];

        byte[] dataNEB = new byte[16];
        byte[] dataDAB = new byte[16];
        String returnString = "";

        System.out.println("BLOCK DECRYPTION");
        for (int i = 0; i < len; i++) {
            int flag = 1;
            System.out.println("BLOCK " + i);

            //ja zimam datata i ja pretvaram vo byte array block po block
            dataNEB = data.substring(borderLeft, borderRight).getBytes(StandardCharsets.UTF_8);
            Counter++;
            CTRString = Counter.toString();
            for (int j = CTRString.length(); j < 16; j++) {
                CTRString += "0";
            }
            CTRbytes = AES.encrypt(CTRString.getBytes(StandardCharsets.UTF_8));


            dataDAB = lista.get(i);                                                         //ENCRYPTED

            for (int j = 0; j < dataDAB.length; j++) {
                decDataBytes[j] = (byte) (CTRbytes[j] ^ dataDAB[j]);
            }
            returnString += decDataBytes.toString();

            for (int j = 0; j < 16; j++) {
                if (dataNEB[j] != decDataBytes[j])
                    flag = 0;
            }
            if (flag == 1)
                System.out.println("\tTRUE");
            else
                System.out.println("\tFALSE");
            borderLeft += 16;
            borderRight += 16;
        }
        return returnString;


    }

    private static void checkMIC(byte[] MIC, String HEADER, byte[] IV, String data, byte[] CTRbytes) {
        System.out.println("VERIFYING MIC...");
        byte[] MIC2 = MICalc(IV, HEADER, CTRbytes, data);

        for (int i = 0; i < 8; i++) {
            if (MIC[i] != MIC2[i]) {
                System.out.println("COMPROMISED");
                return;
            }
        }
        System.out.println("NOT COMPROMISED");

    }

    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException {

        ClearTextFrame ctf = new ClearTextFrame();
        ctf.generateFrame();
        SecureRandom rand = new SecureRandom();

        byte[] IV = new byte[16];
        rand.nextBytes(IV);
        byte[] encIV = new byte[16];
        encIV = AES.encrypt(IV);                                                           //encrypted IV

        Integer CTR = rand.nextInt(100000);
        String CTRString = CTR.toString();
        for (int i = CTRString.length(); i < 16; i++) {
            CTRString += "0";
        }
        byte[] CTRbytes = new byte[8];
        CTRbytes = AES.encrypt(CTRString.getBytes(StandardCharsets.UTF_8));               //CTR ENCRYPTED

        byte[] MIC = MICalc(encIV, ctf.getHeader(), CTRbytes, ctf.getFrameData());        //FINAL MIC

        EncryptedFarme enf = new EncryptedFarme(CTR, CTRbytes);

        enf.sendEncrypted();

        String data = decryptDATA(CTR, enf.getLista());
        checkMIC(MIC, HEADER, encIV, data, CTRbytes);
    }
}