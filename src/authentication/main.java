/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package authentication;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.sound.sampled.Line;
import jsonParser.JSONObject;

/**
 *
 * @author Pierre-Marc Bonneau
 */
public class main {

    /**
     * @param args the command line arguments
     */
    public static String SessionID;
    
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, InvalidAlgorithmParameterException, BadPaddingException, Exception 
    {      
        int OptionChoiceMenuA = 0;
        int OptionChoiceMenuB = 3;
        
        while (OptionChoiceMenuB == 3)
        {
            OptionChoiceMenuB = 0;
            System.out.printf("1. Mot de passe" + '\n');
            System.out.printf("2. Ms-CHAP-v2" + '\n');
            System.out.printf("3. UAF" + '\n');
            System.out.printf("4. Quitter" + '\n');

            Scanner InputReader = new Scanner(System.in);  
            System.out.println("Enter a number: ");
            OptionChoiceMenuA = InputReader.nextInt();       

            switch (OptionChoiceMenuA) 
            {
                case 1:
                    OptionChoiceMenuA = 0;
                    System.out.printf("1. Enregistrer un nouveau compte" + '\n');
                    System.out.printf("2. Authentification" + '\n');
                    System.out.printf("3. Menu précédent" + '\n');
                    System.out.printf("4. Quitter" + '\n');
                    System.out.println("Enter a number: ");
                    OptionChoiceMenuB = InputReader.nextInt();
                    if (OptionChoiceMenuB == 1)
                    { 
                        InputReader.reset();
                        System.out.println("Enter User ID :");
                        String UserID = InputReader.next();
                        System.out.println("Enter User Password :");
                        String UserPassword = InputReader.next();

                        communication CommAddNewRecord = new communication("E", "C", "S");
                        CommAddNewRecord.UserID = UserID;
                        CommAddNewRecord.Password = UserPassword;
                        System.out.printf(CommAddNewRecord.getQuery());
                        communication Result = AddRecordPassword(CommAddNewRecord, UserID, UserPassword);
                        System.out.printf(Result.getAnswer());
                    }
                    else
                    if (OptionChoiceMenuB == 2)
                    { 
                        InputReader.reset();
                        System.out.println("Enter User ID :");
                        String UserID = InputReader.next();
                        System.out.println("Enter User Password :");
                        String UserPassword = InputReader.next();

                        communication CommAuthenticate = new communication("A", "C", "S");
                        CommAuthenticate.UserID = UserID;
                        CommAuthenticate.Password = UserPassword;
                        CommAuthenticate.SessionID = generateFiveDigitsRandomNumber();
                        SessionID = CommAuthenticate.SessionID;
                        System.out.printf(CommAuthenticate.getQuery());
                        communication Result = AuthenticatePassword(CommAuthenticate, UserID, UserPassword);
                        System.out.printf(Result.getAnswer());
                        
                        boolean EndTransactions = false;
                        communication CommTransaction = new communication("T", "C", "S");
                        while (EndTransactions == false)
                        {
                            InputReader.reset();
                            System.out.println("Enter transaction command :");
                            String TransactionCommand = InputReader.next();
                            
                            if (TransactionCommand.equals("end"))
                            {
                                System.out.println("End transaction");
                                break;
                            }
                            
                            System.out.println("Enter session cookie :");
                            String SessionCookie = InputReader.next();
                            CommTransaction.SessionID = SessionID;
                            CommTransaction.TransactionCommand = TransactionCommand;
                            CommTransaction.SessionCookie = CommAuthenticate.SessionCookie;
                            System.out.printf(CommTransaction.getQuery());

                            if (SessionCookie.equals(CommTransaction.SessionCookie))
                            {
                                CommTransaction.Code = Integer.toString(200);
                            }
                            else
                            {
                                CommTransaction.Code = Integer.toString(401);
                            }
                            System.out.printf(CommTransaction.getAnswer());
                        }
                        
                    }
                    OptionChoiceMenuB = 3;
                    break;
                case 2:
                    OptionChoiceMenuA = 0;
                    System.out.printf("1. Enregistrer un nouveau compte" + '\n');
                    System.out.printf("2. Authentification" + '\n');
                    System.out.printf("3. Menu précédent" + '\n');
                    System.out.printf("4. Quitter" + '\n');
                    System.out.println("Enter a number: ");
                    OptionChoiceMenuB = InputReader.nextInt();
                    if (OptionChoiceMenuB == 1)
                    { 
                        InputReader.reset();
                        System.out.println("Enter User ID :");
                        String UserID = InputReader.next();
                        System.out.println("Enter User Password :");
                        String UserPassword = InputReader.next();

                        communication CommAddNewRecord = new communication("E", "C", "S");
                        CommAddNewRecord.UserID = UserID;
                        CommAddNewRecord.Password = UserPassword;
                        System.out.printf(CommAddNewRecord.getQuery());
                        communication Result = AddRecordChallengeResponse(CommAddNewRecord, UserID, UserPassword);
                        System.out.printf(Result.getAnswer());
                    }
                    else
                    if (OptionChoiceMenuB == 2)
                    {
                        InputReader.reset();
                        System.out.println("Enter User ID :");
                        String UserID = InputReader.next();
                        System.out.println("Enter User Password :");
                        String UserPassword = InputReader.next();   

                        communication CommAuthenticate = new communication("A", "C", "S");
                        CommAuthenticate.UserID = UserID;
                        CommAuthenticate.SessionID = generateFiveDigitsRandomNumber();
                        SessionID = CommAuthenticate.SessionID;
                        System.out.printf(CommAuthenticate.getQuery());
                        
                        String ServerNonce = generateFiveDigitsRandomNumber();
                        CommAuthenticate.ServerNonce = ServerNonce;
                        System.out.printf(CommAuthenticate.getAnswer());
                          
                        MessageDigest Digest = MessageDigest.getInstance("MD5");
                        byte[] Hash = Digest.digest(UserPassword.getBytes(StandardCharsets.UTF_8));
                        UserPassword = Base64.getEncoder().encodeToString(Hash);
                        
                        String AuthInfoClientAttendu = SessionID + ServerNonce + UserPassword;
                        
                        MessageDigest SecondaryDigest = MessageDigest.getInstance("SHA1");
                        byte[] SecondaryHash = SecondaryDigest.digest(AuthInfoClientAttendu.getBytes(StandardCharsets.UTF_8));
                        AuthInfoClientAttendu = Base64.getEncoder().encodeToString(SecondaryHash);
                        CommAuthenticate.Password = AuthInfoClientAttendu;
                        
                        String ClientNonce = generateFiveDigitsRandomNumber();
                        CommAuthenticate.ClientNonce = ClientNonce;
                        
                        CommAuthenticate.UserID = "";
                        System.out.printf(CommAuthenticate.getQuery());
                        communication Result = AuthenticateChallengeResponse(CommAuthenticate, UserID, UserPassword);
                        
                        String SessionCookie = generateFiveDigitsRandomNumber();
                        Result.setSessionCookie(SessionCookie);
                        
                        System.out.printf(Result.getAnswer());
                        
                        boolean EndTransactions = false;
                        communication CommTransaction = new communication("T", "C", "S");
                        
                        String VerificationInfoClientExpected =  SessionID + Result.ClientNonce + UserPassword;
                        byte[] VerificationHash = SecondaryDigest.digest(VerificationInfoClientExpected.getBytes(StandardCharsets.UTF_8));
                        VerificationInfoClientExpected = Base64.getEncoder().encodeToString(VerificationHash);
                        
                        while (EndTransactions == false && VerificationInfoClientExpected.equals(Result.VerificationInfo))
                        {
                            InputReader.reset();
                            System.out.println("Enter transaction command :");
                            String TransactionCommand = InputReader.next();
                            
                            if (TransactionCommand.equals("end"))
                            {
                                System.out.println("End transaction");
                                break;
                            }
                            
                            System.out.println("Enter session cookie :");
                            SessionCookie = InputReader.next();
                            CommTransaction.SessionID = SessionID;
                            CommTransaction.TransactionCommand = TransactionCommand;
                            CommTransaction.SessionCookie = CommAuthenticate.SessionCookie;
                            System.out.printf(CommTransaction.getQuery());

                            if (SessionCookie.equals(CommTransaction.SessionCookie))
                            {
                                CommTransaction.Code = Integer.toString(200);
                            }
                            else
                            {
                                CommTransaction.Code = Integer.toString(401);
                            }
                            System.out.printf(CommTransaction.getAnswer());
                        }
                    }
                    break;
                case 3:
                    OptionChoiceMenuA = 0;
                    System.out.printf("1. Enregistrer un nouveau compte" + '\n');
                    System.out.printf("2. Authentification" + '\n');
                    System.out.printf("3. Menu précédent" + '\n');
                    System.out.printf("4. Quitter" + '\n');
                    System.out.println("Enter a number: ");
                    OptionChoiceMenuB = InputReader.nextInt();
                    if (OptionChoiceMenuB == 1)
                    { 
                        InputReader.reset();
                        System.out.println("Enter User ID :");
                        String UserID = InputReader.next();
                        System.out.println("Enter private key password :");
                        String PrivateKeyPassword = InputReader.next();
                        String PrivateKeyIV = "";
                        generatePublicPrivateKeyPair("RSA", 1024,PrivateKeyIV,PrivateKeyPassword);
                        
                    }
                    break;
                case 4:
                    System.out.println("4");
                    break;
                default:
                    break;
            }
        }
    }
    
    // https://gist.github.com/liudong/3993726
    private static void generatePublicPrivateKeyPair(String keyAlgorithm, int numBits, String PrivateKeyEncryptionIV, String PrivateKeyEncryptionPassword) throws IOException, Exception
    {
        try 
        {
            // Get the public/private key pair

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyAlgorithm);

            keyGen.initialize(numBits);

            KeyPair keyPair = keyGen.genKeyPair();

            PrivateKey privateKey = keyPair.getPrivate();

            PublicKey publicKey = keyPair.getPublic();



            System.out.println("\n" + "Generating key/value pair using " + privateKey.getAlgorithm() + " algorithm");



            // Get the bytes of the public and private keys

            byte[] privateKeyBytes = privateKey.getEncoded();

            byte[] publicKeyBytes = publicKey.getEncoded();



            // Get the formats of the encoded bytes

            String formatPrivate = privateKey.getFormat(); // PKCS#8
            String formatPublic = publicKey.getFormat(); // X.509

                
            FileWriter WritePublicKey = new FileWriter("client.txt", true);
            WritePublicKey.write(Base64.getEncoder().encodeToString(publicKeyBytes));
            WritePublicKey.close();
            
            //System.out.println(Base64.getEncoder().encodeToString(privateKeyBytes));
            
            String EncryptedPrivateKey = doEncryption(Base64.getEncoder().encodeToString(privateKeyBytes), PrivateKeyEncryptionPassword);
            //String DecryptedPrivateKey = doDecryption(EncryptedPrivateKey,PrivateKeyEncryptionPassword);
            //System.out.println(DecryptedPrivateKey);
            
            FileWriter WritePrivateKey = new FileWriter("server.txt", true);
            WritePrivateKey.write(EncryptedPrivateKey);
            WritePrivateKey.close();

            //System.out.println("Private Key : " + Base64.getEncoder().encodeToString(privateKeyBytes));
            //System.out.println("Public Key : " + Base64.getEncoder().encodeToString(publicKeyBytes));



            // The bytes can be converted back to public and private key objects

           // KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);

            //EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

            //PrivateKey privateKey2 = keyFactory.generatePrivate(privateKeySpec);



            //EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);

            //PublicKey publicKey2 = keyFactory.generatePublic(publicKeySpec);



            // The original and new keys are the same

            //System.out.println("  Are both private keys equal? " + privateKey.equals(privateKey2));

           // System.out.println("  Are both public keys equal? " + publicKey.equals(publicKey2));

        } 
        //catch (InvalidKeySpecException specException) 
        //{

        //    System.out.println("Exception");

        //    System.out.println("Invalid Key Spec Exception");

        //} 
        catch (NoSuchAlgorithmException e) 
        {

            System.out.println("Exception");

            System.out.println("No such algorithm: " + keyAlgorithm);

        }
     }
    
    // This method encrypts a string using a key.
    // Based from https://gist.github.com/itarato/abef95871756970a9dad
    public static String doEncryption(String plainText, String key) throws Exception 
    {
        byte[] clean = plainText.getBytes();

        // Generating random IV.
        int ivSize = 16;
        byte[] iv = new byte[ivSize];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // Hashing the key to make it fixed size.
        MessageDigest Hash = MessageDigest.getInstance("SHA-256");
        Hash.update(key.getBytes("UTF-8"));
        byte[] KeyBytes = new byte[16];
        System.arraycopy(Hash.digest(), 0, KeyBytes, 0, KeyBytes.length);
        SecretKeySpec secretKeySpec = new SecretKeySpec(KeyBytes, "AES");

        // Set cipher to use AES/CBC/PKCS5Padding.
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        
        // Encrypt string.
        byte[] EncryptedString = cipher.doFinal(clean);

        // Concatenate IV and key.
        byte[] EncryptedIVAndText = new byte[ivSize + EncryptedString.length];
        System.arraycopy(iv, 0, EncryptedIVAndText, 0, ivSize);
        System.arraycopy(EncryptedString, 0, EncryptedIVAndText, ivSize, EncryptedString.length);
        
        // Return IV and key encoded into a string.
        return Base64.getEncoder().encodeToString(EncryptedIVAndText);
    }
    
    // This method decrypts a string using an IV with key.
    // Based from https://gist.github.com/itarato/abef95871756970a9dad
    public static String doDecryption(String encryptedIvTextBytes, String key) throws Exception 
    {
        int ivSize = 16;
        int keySize = 16;

        // Decoding IV and key into byte array.
        byte[] IvAndKeyArray = Base64.getDecoder().decode(encryptedIvTextBytes);
        
        // Rebuilding IvParameterSpec from IV in concatenated IV and key byte array.
        byte[] iv = new byte[ivSize];
        System.arraycopy(IvAndKeyArray, 0, iv, 0, iv.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        int EncryptedSize = IvAndKeyArray.length - ivSize;
        byte[] EncryptedBytes = new byte[EncryptedSize];
        
        // Getting key bytes from concatenated IV and key byte array.
        System.arraycopy(IvAndKeyArray, ivSize, EncryptedBytes, 0, EncryptedSize);

        // Hashing key bytes.
        byte[] KeyBytes = new byte[keySize];
        MessageDigest Hash = MessageDigest.getInstance("SHA-256");
        Hash.update(key.getBytes());
        System.arraycopy(Hash.digest(), 0, KeyBytes, 0, KeyBytes.length);
        
        // Rebuilding SecretKey from hashed key bytes.
        SecretKeySpec secretKeySpec = new SecretKeySpec(KeyBytes, "AES");

        // Set cipher to use AES/CBC/PKCS5Padding.
        Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        
        // Decrypt string.
        byte[] Decrypted = cipherDecrypt.doFinal(EncryptedBytes);

        return new String(Decrypted);
    }
    
    public static communication AddRecordPassword(communication ClientInitialCommunication, String UserID, String UserPassword) throws NoSuchAlgorithmException, IOException
    {
        MessageDigest Digest = MessageDigest.getInstance("SHA1");
        byte[] Hash = Digest.digest(UserPassword.getBytes(StandardCharsets.UTF_8));
        UserPassword = Base64.getEncoder().encodeToString(Hash);

        FileWriter writefile = new FileWriter("keybag.txt", true);
        FileReader readfile = new FileReader("keybag.txt");

        // Creating new JSON object to store encrypted info.
        JSONObject obj = new JSONObject();
        obj.put("UserID", UserID);
        obj.put("UserPassword", UserPassword);
        writefile.write(obj.toString());
        writefile.write("\r\n");
        writefile.close();
        ClientInitialCommunication.Code = "200";
        return ClientInitialCommunication;
    }
    
        public static communication AddRecordChallengeResponse(communication ClientInitialCommunication, String UserID, String UserPassword) throws NoSuchAlgorithmException, IOException
    {
        MessageDigest Digest = MessageDigest.getInstance("MD5");
        byte[] Hash = Digest.digest(UserPassword.getBytes(StandardCharsets.UTF_8));
        UserPassword = Base64.getEncoder().encodeToString(Hash);

        FileWriter writefile = new FileWriter("keybag.txt", true);
        FileReader readfile = new FileReader("keybag.txt");

        // Creating new JSON object to store encrypted info.
        JSONObject obj = new JSONObject();
        obj.put("UserID", UserID);
        obj.put("UserPassword", UserPassword);
        writefile.write(obj.toString());
        writefile.write("\r\n");
        writefile.close();
        ClientInitialCommunication.Code = "200";
        return ClientInitialCommunication;
    }
    
    public static communication AuthenticatePassword(communication ClientInitialCommunication, String UserID, String UserPassword) throws NoSuchAlgorithmException, IOException
    {    
        MessageDigest Digest = MessageDigest.getInstance("SHA1");
        byte[] Hash = Digest.digest(UserPassword.getBytes(StandardCharsets.UTF_8));
        UserPassword = Base64.getEncoder().encodeToString(Hash);
        
        Path Path = Paths.get("keybag.txt");
        List<String> lines = Files.readAllLines(Path);
        
        for (int i = 0; i < lines.size(); i++)
        {
            JSONObject obj = new JSONObject(lines.get(i));
            String ReadUserID = obj.get("UserID").toString();
            String ReadUserPassword =  obj.get("UserPassword").toString();
            if(ReadUserID.equals(UserID) && ReadUserPassword.equals(UserPassword))
            {
                String SessionCookie = generateFiveDigitsRandomNumber();
                ClientInitialCommunication.setSessionCookie(SessionCookie);
                ClientInitialCommunication.Code = "200";
                return ClientInitialCommunication;
            }
        }      
        ClientInitialCommunication.Code = "401";       
        return ClientInitialCommunication;
    }
    
    public static communication AuthenticateChallengeResponse(communication ClientInitialCommunication, String UserID, String UserPassword) throws NoSuchAlgorithmException, IOException
    {          
        String AuthInfoClient = SessionID + ClientInitialCommunication.ServerNonce;
        
        Path Path = Paths.get("keybag.txt");
        List<String> lines = Files.readAllLines(Path);
        
        for (int i = 0; i < lines.size(); i++)
        {
            JSONObject obj = new JSONObject(lines.get(i));
            String ReadUserID = obj.get("UserID").toString();
            String ReadAuthInfoClient = obj.get("UserPassword").toString();
            ReadAuthInfoClient = AuthInfoClient + ReadAuthInfoClient;
            MessageDigest SecondaryDigest = MessageDigest.getInstance("SHA1");
            byte[] SecondaryHash = SecondaryDigest.digest(ReadAuthInfoClient.getBytes(StandardCharsets.UTF_8));
            ReadAuthInfoClient = Base64.getEncoder().encodeToString(SecondaryHash);
            
            if(ReadUserID.equals(UserID) && ReadAuthInfoClient.equals(ClientInitialCommunication.Password))
            {
                String VerificationInfoClientExpected =  SessionID + ClientInitialCommunication.ClientNonce + obj.get("UserPassword").toString();
                byte[] VerificationHash = SecondaryDigest.digest(VerificationInfoClientExpected.getBytes(StandardCharsets.UTF_8));
                VerificationInfoClientExpected = Base64.getEncoder().encodeToString(VerificationHash);
                ClientInitialCommunication.VerificationInfo = VerificationInfoClientExpected;
                
                ClientInitialCommunication.Password = "";
                ClientInitialCommunication.ServerNonce = "";
                
                ClientInitialCommunication.Code = "200";
                return ClientInitialCommunication;
            }
        }      
        ClientInitialCommunication.Code = "401";       
        return ClientInitialCommunication;
    }
    
    public static String generateFiveDigitsRandomNumber()
    {
        Random rnd = new Random();
        return Integer.toString(10000 + rnd.nextInt(90000));
    }
}
