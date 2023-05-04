import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

class PrimeNumberGen {
    public long getPrimeNumber(){
        long n = (int) (new Random().nextDouble() * 100) + 250;
        long l;
        l = (long) ((n)*(Math.log(n) + (Math.log(Math.log(n)) -1) + ((Math.log(Math.log(n))-2)/(Math.log(n))) - ((Math.log(Math.log(n)) -21.0/10.0)/Math.log(n)) ));
        for(long i=l;;i++){
            if(isPrime(i)){
                return i;
            }
        }
    }
    private boolean isPrime(long n){
        if(n%2 == 0 || n%3 == 0) return false;
        for(int i=5; i*i<=n; i+=6){
            if(n%i == 0 || n%(i+2)==0) return false;
        }
        return true;
    }
}


class PrimitiveRootGen {
    long pr, p, phi;
    public PrimitiveRootGen(long p){
        this.p = p;
        this.phi = this.p - 1;
        Vector<Long> primitiveRoots =  this.getPrimitiveRoot(this.p, this.phi);
        this.pr = primitiveRoots.get(new Random().nextInt(primitiveRoots.size()));
    }

    public long getPr() {
        return pr;
    }

    private Vector<Long> getPrimitiveRoot(long p, long phi){
        Vector<Long> primeFactors = this.genPrimesFactorsList(phi);
        Vector<Long> primitiveRoots = new Vector<>();
        for(long i = 2;i<p;i++){
            boolean flg = false;
            for(Long l: primeFactors){
                BigInteger iBig = BigInteger.valueOf(i);
                BigInteger phiBig = BigInteger.valueOf(phi/l);
                BigInteger pBig = BigInteger.valueOf(p);
                BigInteger pRootBig = iBig.modPow(phiBig, pBig);
                if(pRootBig.compareTo(BigInteger.valueOf(1))==0){
                    flg = true;
                    break;
                }
            }
            if(!flg)primitiveRoots.add(i);
        }
        return primitiveRoots;
    }

    private Vector<Long> genPrimesFactorsList(long phi){
        Vector<Long> primesFactors = new Vector<>();
        while(phi % 2 == 0){
            primesFactors.add((long) 2);
            phi /= 2;
        }
        for(long i=3;i<=Math.sqrt(phi);i+=2){
            if(phi % i == 0){
                primesFactors.add(i);
                phi /= i;
            }
        }
        if(phi > 2){
            primesFactors.add(phi);
        }
        return primesFactors;
    }
}


class DiffieHellman {
    BigInteger p, alpha;
    public DiffieHellman(){

    }

    public void genPrimeAndPrimitiveRoot(){
        this.p = BigInteger.valueOf(new PrimeNumberGen().getPrimeNumber());
        this.alpha = BigInteger.valueOf(new PrimitiveRootGen(this.p.intValue()).getPr());
    }

    public BigInteger getAliceMessage(BigInteger aliceSecretNumber){        //alhpa na x mod p
        return this.alpha.modPow(aliceSecretNumber, this.p);
    }

    public BigInteger getBobMessage(BigInteger bobSecretNumber){
        return this.alpha.modPow(bobSecretNumber, this.p);                  //alhpa na y mod p
    }

    public BigInteger aliceCalculationOfKey(BigInteger bobMessage, BigInteger aliceSecretNumber){
        return bobMessage.modPow(aliceSecretNumber, this.p);
    }

    public BigInteger bobCalculationOfKey(BigInteger aliceMessage, BigInteger bobSecretNumber){
        return aliceMessage.modPow(bobSecretNumber, this.p);
    }
}


public class STS {

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
        SecureRandom r = new SecureRandom();
        int IDa = r.nextInt(9000);
        int IDb = r.nextInt(9000);
        while (IDa == IDb) {                                                     // make sure its not the same
            IDb = r.nextInt(9000);
        }

        User Alice = new User(IDa);
        User Bob = new User(IDb);

        CA ca = new CA();
        ca.addUser(IDa);
        System.out.println("User Alice added to CA system");                //dodavanje za check later on
        ca.addUser(IDb);
        System.out.println("User Bob added to CA system");
        System.out.println("============================================");

        String message = "this is a secret message";
        Alice.AStart(message, Bob);

    }


    public static class User{
        public Integer ID;
        public KeyPair pair;
        public PublicKey publicKey;
        private final PrivateKey privateKey;
        public DiffieHellman DH;                                 //od kade shto imame prime i primitiveRoot
        public Cipher ASYMcihper = Cipher.getInstance("RSA");
        public Cipher SYMcihper = Cipher.getInstance("AES/ECB/PKCS5Padding");
        public Certificate Cert;
        public BigInteger x;                    //ova vazi samo za Alice...odnosni x shto si go cuva shto e potrebno kaj AliceReceiveData
        public String message;

        User(Integer id) throws NoSuchAlgorithmException, NoSuchPaddingException {
            ID = id;
            DH = new DiffieHellman();
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            pair = generator.generateKeyPair();
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();

        }


        //===========KOMUNIKACIJA
        public void AStart(String message, User Bob) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {          // FIX MESSAGE
            System.out.println("Alice begins effort to communicate with Bob ");
            DH.genPrimeAndPrimitiveRoot();          //p i alpha se generiraat
            SecureRandom rnd = new SecureRandom();
            x = DH.getAliceMessage(BigInteger.valueOf(rnd.nextInt()));       //x za A
            System.out.println("Diffie-Hellman parameters are generated and sent to Bob");
            System.out.println("============================================");

            Bob.BobReceiveData(DH.alpha, DH.p, x, this, message);                 //prakanje do bob alpha, p, x

        }

        public void BobReceiveData(BigInteger alpha, BigInteger p, BigInteger x, User Alice, String msg) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
            message = msg;                  //bob ja ima porakata
            DH.alpha = alpha;               //setiraj da se isti
            DH.p = p;
            SecureRandom rnd = new SecureRandom();
            BigInteger y = DH.getBobMessage(BigInteger.valueOf(rnd.nextInt()));         //y za B                    1

            String XandY = x+","+y;                                 //{αy, αx}
            ASYMcihper.init(Cipher.ENCRYPT_MODE, privateKey);
            String XandY_Signed = Base64.getEncoder().encodeToString(ASYMcihper.doFinal(XandY.getBytes(StandardCharsets.UTF_8)));           //x and y potpisani
            BigInteger key = DH.bobCalculationOfKey(x,y);
            SecretKeySpec SECkey = new SecretKeySpec(Arrays.copyOf(key.toByteArray(),16), "AES");
            SYMcihper.init(Cipher.ENCRYPT_MODE, SECkey);
            String XandY_Signed_and_Encrypted = Base64.getEncoder().encodeToString(SYMcihper.doFinal(XandY_Signed.getBytes(StandardCharsets.UTF_8)));//            3

            Cert = CA.generateCert(ID, publicKey ,alpha, p);                       //CA za Bob
            assert Cert != null;
            String CertString = Cert.toString();                                    //                              2

            ArrayList<String> data = new ArrayList<>();
            data.add(y.toString());
            data.add(CertString);
            data.add(XandY_Signed_and_Encrypted);

            System.out.println("Bob creates |   αy, CertB, EK(sB{αy, αx})   | and sends it to Alice");
            System.out.println("============================================");

            Alice.AliceReceiveData(data, this);                   //y, CertB, enc
        }

        public void AliceReceiveData(ArrayList<String> data, User Bob) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException {
            Cert = CA.generateCert(ID, publicKey ,DH.alpha, DH.p);
            assert Cert != null;
            String CertString = Cert.toString();                    //cert za Alice

            String XandY = x.toString()+","+data.get(0);                            //SEGA IMAAT ISTI KLUC t.e. vrednost za simetricna kriptografija
            ASYMcihper.init(Cipher.ENCRYPT_MODE, privateKey);
            String XandY_Signed = Base64.getEncoder().encodeToString(ASYMcihper.doFinal(XandY.getBytes(StandardCharsets.UTF_8)));       //SIGNED
            BigInteger key = DH.aliceCalculationOfKey(x,BigInteger.valueOf(Long.parseLong(data.get(0))));
            SecretKeySpec SECkey = new SecretKeySpec(Arrays.copyOf(key.toByteArray(),16), "AES");
            SYMcihper.init(Cipher.ENCRYPT_MODE, SECkey);
            String XandY_Signed_and_Encrypted = Base64.getEncoder().encodeToString(SYMcihper.doFinal(XandY_Signed.getBytes(StandardCharsets.UTF_8)));       //ENC

            ArrayList<String> dataFinal = new ArrayList<>();
            dataFinal.add(CertString);
            dataFinal.add(XandY_Signed_and_Encrypted);

            System.out.println("Alice creates |   CertA, EK(sA{αx, αy})   | and sends it to Bob");
            System.out.println("============================================");

            BobFinal(dataFinal, Bob);                           //usthe sme kaj alice
        }

        public void BobFinal(ArrayList<String> dataFinal, User Bob) {
            System.out.println("Verification of Diffie-Hellman parameters");
            String CertData[] = dataFinal.get(0).split(",");
            BigInteger alpha =  BigInteger.valueOf(Long.parseLong(CertData[1]));
            BigInteger P = BigInteger.valueOf(Long.parseLong(CertData[2]));
            if (Bob.DH.alpha.equals(alpha) && Bob.DH.p.equals(P)){                              //proveruva od Cert na alice
                System.out.println("\tParamaters alpha and P from first message match");
                System.out.println("\tThe message did in fact came from Alice");
                System.out.println("\t"+Bob.message);
            }
            else{
                System.out.println("\tParamaters alpha and P from first message DO NOT match");
                System.out.println("\tThe message did not came from Alice");
            }

        }

    }


    public static class CA{                                                           //ke treba da pravi i izdava Certs
        public KeyPair pair;
        public PublicKey publicKey;
        private static PrivateKey privateKey;
        public static ArrayList<Integer> Users;                                         //site korisnici vo CA
        public static Cipher ASYMcihper;
        public CA() throws NoSuchAlgorithmException, NoSuchPaddingException {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");       //generiranje priv i pub key
            generator.initialize(2048);                                     //The generated key will have a size of 2048 bits.
            pair = generator.generateKeyPair();
            publicKey = pair.getPublic();
            privateKey = pair.getPrivate();
            Users = new ArrayList<>();
            ASYMcihper = Cipher.getInstance("RSA");
        }

        public static Certificate generateCert(Integer id, PublicKey PK,BigInteger alpha, BigInteger p) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
            if(Users.contains(id)){                                                       // proverka na user dali e vo CA
                ASYMcihper.init(Cipher.ENCRYPT_MODE, privateKey);                       //sign na Certs od strana na CA
                String dataBeforeSign = id+","+alpha+","+p;
                //String dataBeforeSign = id+","+PK+","+alpha+","+p;
                //treba da stoi ova tuka
                String dataSigned = Base64.getEncoder().encodeToString(ASYMcihper.doFinal(dataBeforeSign.getBytes(StandardCharsets.UTF_8)));

                return new Certificate(id, PK ,alpha, p, dataSigned);
            }
            else{                                                                   //ako e neka prati Cert, vo sprotivno error
                System.out.println("user not in CA");
                return null;
            }

        }

        public void addUser(Integer id){
            Users.add(id);
        }
    }


    public static class Certificate{            //      (Alice, pA, α, p, sT{Alice, pA, α, p})
        public Integer ID;
        public PublicKey PK;
        public BigInteger alpha;
        public BigInteger P;

        public String DataSigned;

        public Certificate(Integer id, PublicKey pk,BigInteger a, BigInteger p, String dataSigned){
            ID = id;
            PK = pk;
            alpha = a;
            P = p;
            DataSigned = dataSigned;
        }

        public Integer getID() {
            return ID;
        }

        public BigInteger getAlpha() {
            return alpha;
        }

        public BigInteger getP() {
            return P;
        }

        public PublicKey getPK(){
            return PK;
        }

        @Override
        public String toString() {
            return ID+","+alpha+","+P+","+DataSigned;
            //return ID+","+PK+","+alpha+","+P+","+DataSigned;
        }
    }
}
