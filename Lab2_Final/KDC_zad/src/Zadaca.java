import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

public class Zadaca {

    public static String Ya;
    public static String Yb;
    public static String YAB;
    public static String Y;

    public static void main(String[] args) throws ParseException {
        SecureRandom r = new SecureRandom();
        int IDa = r.nextInt(9000);
        int IDb = r.nextInt(9000);
        while (IDa == IDb) {                                                     // make sure its not the same
            IDb = r.nextInt(9000);
        }

        KDC kdc = new KDC();
        User Alice = new User(IDa);
        User Bob = new User(IDb);
        Alice.SetKEK(kdc.AddUser(IDa));
        Bob.SetKEK(kdc.AddUser(IDb));
        Alice.verif.add(IDb);                                                //za verifikacija na ID posle
        Bob.verif.add(IDa);

        kdc.Request(IDa, IDb, Alice.GenerateNonce());                           // prakanje request do kdc

        Alice.VerifyAlice();                                                    //verifikacija od strana na alice
        System.out.println("Alice verification complete, now sending YAB and Yb to Bob");
        System.out.println("=====================");

        boolean FLAG = Bob.VerifyBob();                                         //verifikacija on strana na bob
        if (FLAG) {
            String messsage;
            Y = Alice.SendMessage("this is a secret message");
            messsage = Bob.RecieveMessage();
            if (messsage.equals("X")) {
                System.out.println("Message not received. Something went wrong");
            } else {
                System.out.println("Message successfully received : ");
                System.out.println("\t" + messsage);
            }
        } else {
            System.out.println("Something went wrong with Bob's verification");
        }
    }


    public static class User {
        public Date T;
        public Integer ID;
        public String RA;
        public SecretKeySpec KEK;
        public static SecretKeySpec Kses;
        public ArrayList<Integer> verif;

        User(Integer id) {
            ID = id;
            verif = new ArrayList<>();
        }

        public String GenerateNonce() {                                                              //nonce = RA
            SecureRandom secureRandom = new SecureRandom();
            StringBuilder stringBuilder = new StringBuilder();
            for (int i = 0; i < 16; i++) {
                stringBuilder.append(secureRandom.nextInt(10));
            }
            RA = stringBuilder.toString();
            return RA;
        }

        public void SetKEK(SecretKeySpec Kek) {
            KEK = Kek;
        }

        public void VerifyAlice() throws ParseException {
            System.out.println("ALice has recieved Ya and Yb");
            String data = Decrypt(Ya, KEK);
            String dataArray[] = data.split(",");                   //0-Kses, 1-ra, 2-T, 3-ID

            //---------------------RA
            if (dataArray[1].equals(RA)) {
                System.out.println("RA is correct for Ya");
            } else {
                System.out.println("RA is incorrect for Ya");
            }

            //---------------------T
            Date Ts = new Date();                                                            //novo generiran
            DateFormat format = new SimpleDateFormat("EEE MMM dd HH:mm:ss z yyyy", Locale.ENGLISH);
            T = format.parse(dataArray[2]);                                                //toa shto prakjame
            if ((T.getTime() - Ts.getTime()) <= 600000) {                 //600000 ms = 10 min
                System.out.println("T is confirmed for Ya");
            } else {
                System.out.println("T does not match for Ya");
            }

            //----------------------ID
            if (verif.contains(Integer.parseInt(dataArray[3]))) {
                System.out.println("ID:" + dataArray[3] + " is a valid user");
            } else {
                System.out.println(dataArray[3] + " is not a valid user");
            }

            //----------------------Kses za A
            SetKses(dataArray[0]);

            // treba da napravime YAB i so noviet Kses da gi enkriptirame IDa i Ts i da pratime na Bob
            String stringYAB = ID.toString() + "," + Ts.toString();
            YAB = Encrypt(stringYAB, Kses);
        }

        public boolean VerifyBob() throws ParseException {
            System.out.println("Bob recieves YAB and Yb");
            String data = Decrypt(Yb, KEK);                     //yb   -   Kses,T,IDa
            String dataArray[] = data.split(",");

            //---------------------T
            Date Ts = new Date();
            DateFormat format = new SimpleDateFormat("EEE MMM dd HH:mm:ss z yyyy", Locale.ENGLISH);
            T = format.parse(dataArray[1]);
            if ((T.getTime() - Ts.getTime()) <= 600000) {                   //600000 ms = 10 min
                System.out.println("T is confirmed for Yb");
            } else {
                return false;
            }

            //----------------------ID
            Integer IDa = Integer.parseInt(dataArray[2]);
            if (verif.contains(IDa)) {                                                                  //prvo za proverka vo KDC
                System.out.println("ID:" + dataArray[2] + " is a valid user");
            } else {
                return false;
            }

            //----------------------Kses za B
            SetKses(dataArray[0]);


            //----------------------Rabota so YAB
            data = Decrypt(YAB, Kses);
            dataArray = data.split(",");                      //YAB  -   ID,T

            //----------------------ID
            if (IDa == Integer.parseInt(dataArray[0])) {                                               //vtoro za sporeduvanje dali ID-ata se isti
                System.out.println("ID's match");
            } else {
                return false;
            }

            //---------------------Ts
            Ts = new Date();
            T = format.parse(dataArray[1]);
            if ((T.getTime() - Ts.getTime()) <= 600000) {                  //600000 ms = 10 min
                System.out.println("Ts is confirmed for YAB");
            } else {
                return false;
            }
            System.out.println("=====================");
            return true;
        }

        public String SendMessage(String msg) {
            Date Ts = new Date();
            String date = Ts.toString();
            String M = msg + "," + date;

            return Encrypt(M, Kses);
        }

        public String RecieveMessage() throws ParseException {
            String C = Decrypt(Y, Kses);
            String dataC[] = C.split(",");

            //---------------------T
            Date Ts = new Date();
            DateFormat format = new SimpleDateFormat("EEE MMM dd HH:mm:ss z yyyy", Locale.ENGLISH);
            T = format.parse(dataC[1]);
            if (!(T.getTime() - Ts.getTime() <= 600000)) {
                return "X";
            }

            return dataC[0];
        }

        public static String Encrypt(String strToEncrypt, SecretKeySpec Key) {
            try {
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, Key);
                return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
            } catch (Exception e) {
                System.out.println("Error while encrypting: " + e.toString());
            }
            return null;
        }


        public static String Decrypt(String strToDecrypt, SecretKeySpec Key) {
            try {
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
                cipher.init(Cipher.DECRYPT_MODE, Key);
                return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
            } catch (Exception e) {
                System.out.println("Error while decrypting: " + e.toString());
            }
            return null;
        }

        public static void SetKses(String Key) {
            byte[] key = Key.getBytes();
            MessageDigest sha = null;
            try {
                sha = MessageDigest.getInstance("SHA-256");
                key = sha.digest(key);
                key = Arrays.copyOf(key, 16);
                SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
                Kses = secretKey;
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
    }


    public static class KDC {
        public static ArrayList<Integer> IDs;
        public static ArrayList<SecretKeySpec> KEKs;                        //site kekovci se cuvaat

        KDC() {
            IDs = new ArrayList<>();
            KEKs = new ArrayList<>();
        }

        public static void SetKey(String Key) {
            byte[] key = Key.getBytes();
            MessageDigest sha = null;
            try {
                sha = MessageDigest.getInstance("SHA-256");
                key = sha.digest(key);
                key = Arrays.copyOf(key, 16);
                SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
                KEKs.add(secretKey);                                            //KEK se dodava i ne se menja
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }

        public static String Encrypt(String strToEncrypt, SecretKeySpec Key) {
            try {
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, Key);
                return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
            } catch (Exception e) {
                System.out.println("Error while encrypting: " + e.toString());
            }
            return null;
        }

        public String NewKey() {                                                 //random new alhpanumeric key
            String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789" + "abcdefghijklmnopqrstuvxyz";
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 32; i++) {
                int index = (int) (AlphaNumericString.length() * Math.random());
                sb.append(AlphaNumericString.charAt(index));
            }
            return sb.toString();
        }

        public SecretKeySpec AddUser(Integer ID) {                   //dodavanje na user i dodavanje na negoviot kluc vo serverot
            SetKey(NewKey());
            IDs.add(ID);
            return KEKs.get(KEKs.size() - 1);                       //vednash vrakanje odma koga ke go dodade
        }

        public void Request(Integer IDa, Integer IDb, String RA) {
            if (IDs.contains(IDa) && IDs.contains(IDb)) {
                System.out.println("Request accepted");
                SecretKeySpec KEKa = KEKs.get(IDs.indexOf(IDa));                        //kek na korisnik ne se menja ama se koristi za generiranje na dr keys
                SecretKeySpec KEKb = KEKs.get(IDs.indexOf(IDb));
                String Kses = NewKey();                                 //generate random Kses
                Date T = new Date();                                //generate lifetime

                String BeforeEncYa = Kses + "," + RA + "," + T.toString() + "," + IDb.toString();//kaj slika odvoeni se so zapirka vo funkcija taka da ke gi povrzam so zapirka
                String BeforeEncYb = Kses + "," + T + "," + IDa.toString();

                Ya = Encrypt(BeforeEncYa, KEKa);
                Yb = Encrypt(BeforeEncYb, KEKb);

                System.out.println("Ya and Yb have been generated and sent to Alice");
                System.out.println("=====================");
            }
            else {
                System.out.println("Users arent in KDC");
            }
        }
    }
}
