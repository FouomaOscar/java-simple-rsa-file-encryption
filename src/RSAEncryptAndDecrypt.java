import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.logging.Logger;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSAEncryptAndDecrypt {

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        return pair;
    }

    public static KeyPair getKeyPairFromKeyStore() throws Exception {
        //Generated with:
        //  keytool -genkeypair -alias mykey -storepass s3cr3t -keypass s3cr3t -keyalg RSA -keystore keystore.jks

        InputStream ins = RSAEncryptAndDecrypt.class.getResourceAsStream("/keystore.jks");

        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(ins, "s3cr3t".toCharArray());   //Keystore password
        KeyStore.PasswordProtection keyPassword =       //Key password
                new KeyStore.PasswordProtection("s3cr3t".toCharArray());

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("mykey", keyPassword);

        java.security.cert.Certificate cert = keyStore.getCertificate("mykey");
        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return new KeyPair(publicKey, privateKey);
    }

    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
//        byte[] bytes = new byte[117];
        byte[] bytes = Base64.getDecoder().decode(cipherText.trim());

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }


    public static void main (String args []) throws Exception {
        //First generate a public/private key pair
        KeyPair pair = generateKeyPair();
        //KeyPair pair = getKeyPairFromKeyStore();

        //Our secret message
        String message = new String(Files.readAllBytes(Paths.get("D:\\WORKSPACE\\rsaEncryptAndDecryption\\hello.txt")));

        //Encrypt the message
        String cipherText = encrypt(message, pair.getPublic());

//        write answer on file
//        FileOutputStream out = new FileOutputStream("name");
//        byte[] bytes = Base64.getDecoder().decode(cipherText);
//        out.write(bytes);

        List<String> lines = Arrays.asList(cipherText);
        Path file = Paths.get("name");
        Files.write(file, lines, UTF_8);

//        get encrypt from file before decrypt
        String answer = new String(Files.readAllBytes(Paths.get("D:\\WORKSPACE\\rsaEncryptAndDecryption\\name")));
        System.out.println(answer);

        //Now decrypt it
        String decipheredMessage = decrypt(answer, pair.getPrivate());

        System.out.println("test reeponse" + decipheredMessage);

        //Let's sign our message
        String signature = sign("foobar", pair.getPrivate());

        //Let's check the signature
        boolean isCorrect = verify("foobar", signature, pair.getPublic());
        System.out.println("Signature correct: " + isCorrect);
//        try {
//            RSAEncryptAndDecrypt rsaEncryptAndDecrypt = new RSAEncryptAndDecrypt();
////            rsaEncryptAndDecrypt.saveFile();
//            rsaEncryptAndDecrypt.encryptFile(Files.readAllBytes(Paths.get(".//hello.txt"));
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        } catch (NoSuchPaddingException e) {
//            e.printStackTrace();
//        } catch (IOException e) {
//            e.printStackTrace();
//        } catch (BadPaddingException e) {
//            e.printStackTrace();
//        } catch (IllegalBlockSizeException e) {
//            e.printStackTrace();
//        }
    }

//    logic with read and write on file

//    PublicKey pub;
//    PrivateKey PrivateKey;
//    KeyPair kp;
//    KeyPairGenerator kpg;
//    String fileBase ="RSA_key";
//    private File verFile;
//    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//
//    public RSAEncryptAndDecrypt() throws NoSuchAlgorithmException, NoSuchPaddingException {
//        kpg = KeyPairGenerator.getInstance("RSA");
//        kpg.initialize(2048);
//        kp = kpg.generateKeyPair();
//
//        PublicKey pub = kp.getPublic();
//        PrivateKey privateKey = kp.getPrivate();
////        System.out.println(pub);
////        System.out.println("*");
////        System.out.println("*");
////        System.out.println("*");
////        System.out.println(privateKey);
//    }

    //    public void saveFile() throws IOException {
//        try (FileOutputStream out = new FileOutputStream(fileBase + ".key")) {
//            out.write(kp.getPrivate().getEncoded());
//        }
//
//        try (FileOutputStream out = new FileOutputStream(fileBase + ".pub")) {
//            out.write(kp.getPublic().getEncoded());
//        }
//    }
//
//    public PublicKey restorePublicFile(URI pubKeyFile) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
//        byte[] bytes = Files.readAllBytes(Paths.get(pubKeyFile));
//        X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
//        KeyFactory kf = KeyFactory.getInstance("RSA");
//        PublicKey pub = kf.generatePublic(ks);
//        return pub;
//    }
//
//    public void restorePrivateKey(URI pvtKeyFile) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
//        byte[] bytes = Files.readAllBytes(Paths.get(pvtKeyFile));
//        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
//        KeyFactory kf = KeyFactory.getInstance("RSA");
//        PrivateKey pvt = kf.generatePrivate(ks);
//    }

//    public void encryptFile(String inFile) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
//
//        PrivateKey pvt = PrivateKey;
//        cipher.init(Cipher.ENCRYPT_MODE, pvt);
//
//    }
//
//
//    public void decrypt(File encFile) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
//        PublicKey pub = this.pub;
//        cipher.init(Cipher.DECRYPT_MODE, pub);
//        try (FileInputStream in = new FileInputStream(encFile);
//             FileOutputStream out = new FileOutputStream(verFile)) {
//            processFile(cipher, in, out);
//        }
//    }

//    static private void processFile(Cipher ci, InputStream in) throws IllegalBlockSizeException, BadPaddingException, IOException {
//        byte[] ibuf = new byte[1024];
//        int len;
//        while ((len = in.read(ibuf)) != -1) {
//            byte[] obuf = ci.update(ibuf, 0, len);
//            if ( obuf != null ) out.write(obuf);
//        }
//        byte[] obuf = ci.doFinal();
//        if ( obuf != null ) out.write(obuf);
//    }
}
