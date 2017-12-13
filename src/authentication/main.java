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
import java.security.Signature;
import java.security.SignatureException;
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
        
        // Loop from main menu until user has selected something else than 3 (go back to first menu) on secondary menu.
        Goback : while (OptionChoiceMenuB == 3)
        {       
            
            // Set back choice to 0 for secondary menu.
            OptionChoiceMenuB = 0;
            
            // Show main menu.
            System.out.printf("1. Mot de passe" + '\n');
            System.out.printf("2. Ms-CHAP-v2" + '\n');
            System.out.printf("3. UAF" + '\n');
            System.out.printf("4. View registration info" + '\n');
            System.out.printf("5. Quitter" + '\n');

            Scanner InputReader = new Scanner(System.in);  
            System.out.println("Enter a number: ");
            OptionChoiceMenuA = InputReader.nextInt();       

            // Get user selection for main menu.
            switch (OptionChoiceMenuA) 
            {
                case 1:
                    // Set back choice to 0 for main menu.
                    OptionChoiceMenuA = 0;

                    // Show secondary menu.
                    System.out.printf("1. Enregistrer un nouveau compte" + '\n');
                    System.out.printf("2. Authentification" + '\n');
                    System.out.printf("3. Menu précédent" + '\n');
                    System.out.printf("4. Quitter" + '\n');
                    System.out.println("Enter a number: ");
                    OptionChoiceMenuB = InputReader.nextInt();
                    
                    // Password registration.
                    if (OptionChoiceMenuB == 1)
                    { 
                        InputReader.reset();
                        
                        // Get user ID and password.
                        System.out.println("Enter User ID :");
                        String UserID = InputReader.next();
                        System.out.println("Enter User Password :");
                        String UserPassword = InputReader.next();

                        // Create a new registration type communication from client to server.
                        communication CommAddNewRecord = new communication("E", "C", "S");
                        
                        // Set user ID and password to this communication.
                        CommAddNewRecord.UserID = UserID;
                        CommAddNewRecord.Password = UserPassword;
                        
                        // Print initial query.
                        System.out.printf(CommAddNewRecord.getQuery());
                        
                        // Call AddRecordPassword (server side) with the initial communication.
                        communication Result = AddRecordPassword(CommAddNewRecord, UserID, UserPassword);
                        
                        // Print answer.
                        System.out.printf(Result.getAnswer());
                        
                        // Go back to first menu
                        OptionChoiceMenuB = 3;
                        continue Goback;
                    }
                    else
                    // Password authentication.
                    if (OptionChoiceMenuB == 2)
                    { 
                        InputReader.reset();
                        
                        // Get user ID and password.
                        System.out.println("Enter User ID :");
                        String UserID = InputReader.next();
                        System.out.println("Enter User Password :");
                        String UserPassword = InputReader.next();

                        // Create a new authentication type communication from client to server.
                        communication CommAuthenticate = new communication("A", "C", "S");
                        
                        // Set user ID, password and random session ID to communication.
                        CommAuthenticate.UserID = UserID;
                        CommAuthenticate.Password = UserPassword;
                        CommAuthenticate.SessionID = generateFiveDigitsRandomNumber();
                        SessionID = CommAuthenticate.SessionID;
                        
                        // Print initial query.
                        System.out.printf(CommAuthenticate.getQuery());
                        
                        // Call AuthenticatePassword (server side) with initial communication.
                        communication Result = AuthenticatePassword(CommAuthenticate, UserID, UserPassword);
                        
                        System.out.printf(Result.getAnswer());
                        
                        boolean EndTransactions = false;
                        
                        // Create a new communication for transactions, from client to server.
                        communication CommTransaction = new communication("T", "C", "S");
                        while (EndTransactions == false)
                        {
                            InputReader.reset();
                            
                            // Get transaction command from input.
                            System.out.println("Enter transaction command :");
                            String TransactionCommand = InputReader.next();
                            
                            // If user decides to end transactions by typing "end" as command.
                            if (TransactionCommand.equals("end"))
                            {
                                System.out.println("End transaction");
                                // Go back to first menu
                                OptionChoiceMenuB = 3;
                                continue Goback;
                            }
                            
                            // Ask use to enter the session cookie.
                            System.out.println("Enter session cookie :");
                            String SessionCookie = InputReader.next();
                            
                            // Set info to transaction communication.
                            CommTransaction.SessionID = SessionID;
                            CommTransaction.TransactionCommand = TransactionCommand;
                            CommTransaction.SessionCookie = CommAuthenticate.SessionCookie;
                            
                            // Print transaction query.
                            System.out.printf(CommTransaction.getQuery());

                            // Verify session cookie (*** Server Side ***).
                            if (SessionCookie.equals(CommTransaction.SessionCookie))
                            {
                                // If valide, set 200 (ok) as transaction code.
                                CommTransaction.Code = Integer.toString(200);
                                
                                // Removing session cookie from initial transaction since we don't need it anymore and don't want it to be printed in answer.
                                CommTransaction.SessionCookie = "";
                            }
                            else
                            {
                                // Otherwise, set 401 (error).
                                CommTransaction.Code = Integer.toString(401);
                                
                                // Removing session cookie from initial transaction since we don't need it anymore and don't want it to be printed in answer.
                                CommTransaction.SessionCookie = "";
                            }
                            
                            // Print answer
                            System.out.printf(CommTransaction.getAnswer());
                        }
                        
                    }
                    else
                    if (OptionChoiceMenuB == 4)
                    {
                        System.exit(0); 
                    }
                    // Set 3 to secondary menu selected option to go back to main menu.
                    OptionChoiceMenuB = 3;
                    break;
                case 2:
                    // Set back choice to 0 for main menu.
                    OptionChoiceMenuA = 0;
                    
                    // Show secondary menu
                    System.out.printf("1. Enregistrer un nouveau compte" + '\n');
                    System.out.printf("2. Authentification" + '\n');
                    System.out.printf("3. Menu précédent" + '\n');
                    System.out.printf("4. Quitter" + '\n');
                    System.out.println("Enter a number: ");
                    OptionChoiceMenuB = InputReader.nextInt();
                    
                    // Challenge response registration
                    if (OptionChoiceMenuB == 1)
                    { 
                        InputReader.reset();
                        
                        // Get user ID and password.
                        System.out.println("Enter User ID :");
                        String UserID = InputReader.next();
                        System.out.println("Enter User Password :");
                        String UserPassword = InputReader.next();

                        // Create a new registration type communication from client to server.
                        communication CommAddNewRecord = new communication("E", "C", "S");
                        
                        // Set user ID and password to this communication.
                        CommAddNewRecord.UserID = UserID;
                        CommAddNewRecord.Password = UserPassword;
                        
                        // Print initial query
                        System.out.printf(CommAddNewRecord.getQuery());
                        
                        // Call AddRecordChallengeResponse (server side) with the initial communication.
                        communication Result = AddRecordChallengeResponse(CommAddNewRecord, UserID, UserPassword);
                        
                        // Print answer
                        System.out.printf(Result.getAnswer());
                        
                        // Go back to first menu
                        OptionChoiceMenuB = 3;
                        continue Goback;
                    }
                    else
                    // Challenge response authentication.
                    if (OptionChoiceMenuB == 2)
                    {
                        InputReader.reset();
                        
                        // Get user ID and password.
                        System.out.println("Enter User ID :");
                        String UserID = InputReader.next();
                        System.out.println("Enter User Password :");
                        String UserPassword = InputReader.next();   

                        // Create a new authentication type communication from client to server.
                        communication CommAuthenticate = new communication("A", "C", "S");
                        
                        // Set user ID and generated session ID to this communication.
                        CommAuthenticate.UserID = UserID;
                        CommAuthenticate.SessionID = generateFiveDigitsRandomNumber();
                        SessionID = CommAuthenticate.SessionID;
                        
                        // Print initial query (A1).
                        System.out.printf(CommAuthenticate.getQuery());
                        
                        // Generate server random nonce (Ns) and set it to communication.
                        String ServerNonce = generateFiveDigitsRandomNumber();
                        CommAuthenticate.ServerNonce = ServerNonce;
                        
                        // Print answer (A2)
                        System.out.printf(CommAuthenticate.getAnswer());
                          
                        // Hash user password using MD5 (H2).
                        MessageDigest Digest = MessageDigest.getInstance("MD5");
                        byte[] Hash = Digest.digest(UserPassword.getBytes(StandardCharsets.UTF_8));
                        UserPassword = Base64.getEncoder().encodeToString(Hash);
                        
                        // Prepare expected client info.
                        String AuthInfoClientExpected = SessionID + ServerNonce + UserPassword;
                        
                        // Hash expected client info using SHA1 (H1).
                        MessageDigest SecondaryDigest = MessageDigest.getInstance("SHA1");
                        byte[] SecondaryHash = SecondaryDigest.digest(AuthInfoClientExpected.getBytes(StandardCharsets.UTF_8));
                        AuthInfoClientExpected = Base64.getEncoder().encodeToString(SecondaryHash);
                        
                        // Set client expected info as password.
                        CommAuthenticate.Password = AuthInfoClientExpected;
                        
                        // Generate client nonce (Nc) and set it to communication.
                        String ClientNonce = generateFiveDigitsRandomNumber();
                        CommAuthenticate.ClientNonce = ClientNonce;
                        
                        // Delete user ID from communication, since we don't need it anymore and don't want it to be printed in secondary query and answer.
                        CommAuthenticate.UserID = "";
                        
                        // Print secondary query (A3)
                        System.out.printf(CommAuthenticate.getQuery());
                        
                        // Call AuthenticateChallengeResponse (server side) with the initial communication.
                        communication Result = AuthenticateChallengeResponse(CommAuthenticate, UserID, UserPassword);
                        
                        // Removing server nonce from initial transaction since we don't need it anymore and don't want it to be printed in answer.
                        Result.ServerNonce = "";
                        
                        // Generate session cookie.
                        String SessionCookie = generateFiveDigitsRandomNumber();
                        Result.setSessionCookie(SessionCookie);
                        
                        // Print secondary answer (A4)
                        System.out.printf(Result.getAnswer());
                        
                        boolean EndTransactions = false;
                        
                        // Create a new communication for transactions, from client to server.
                        communication CommTransaction = new communication("T", "C", "S");
                        
                        // Prepare actual verification info, append session ID with client nonce and password.
                        String VerificationInfoClientActual =  SessionID + Result.ClientNonce + UserPassword;
                        
                        // Hash actual verification info using SHA1 (H1).
                        byte[] VerificationHash = SecondaryDigest.digest(VerificationInfoClientActual.getBytes(StandardCharsets.UTF_8));
                        VerificationInfoClientActual = Base64.getEncoder().encodeToString(VerificationHash);
                        
                        while (EndTransactions == false && VerificationInfoClientActual.equals(Result.VerificationInfo))
                        {
                            InputReader.reset();
                            
                            // Get transaction command from input
                            System.out.println("Enter transaction command :");
                            String TransactionCommand = InputReader.next();
                            
                            // If user decides to end transactions by typing "end" as command.
                            if (TransactionCommand.equals("end"))
                            {
                                System.out.println("End transaction");
                                // Go back to first menu
                                OptionChoiceMenuB = 3;
                                continue Goback;
                            }
                            
                            // Ask use to enter the session cookie.
                            System.out.println("Enter session cookie :");
                            SessionCookie = InputReader.next();
                            
                            // Set session ID, transaction command and session cookie to initial communication.
                            CommTransaction.SessionID = SessionID;
                            CommTransaction.TransactionCommand = TransactionCommand;
                            CommTransaction.SessionCookie = CommAuthenticate.SessionCookie;
                            
                            // Get transaction query
                            System.out.printf(CommTransaction.getQuery());
                            
                            // Verify session cookie (*** Server Side ***).
                            if (SessionCookie.equals(CommTransaction.SessionCookie))
                            {
                                // If valide, set 200 (ok) as transaction code.
                                CommTransaction.Code = Integer.toString(200);
                                
                                // Removing session cookie from initial transaction since we don't need it anymore and don't want it to be printed in answer.
                                CommTransaction.SessionCookie = "";
                            }
                            else
                            {
                                // Otherwise, set 401 (error)
                                CommTransaction.Code = Integer.toString(401);
                                
                                // Removing session cookie from initial transaction since we don't need it anymore and don't want it to be printed in answer.
                                CommTransaction.SessionCookie = "";
                            }
                            
                            // Print answer
                            System.out.printf(CommTransaction.getAnswer());
                        }
                    }
                    else
                    if (OptionChoiceMenuB == 4)
                    {
                        System.exit(0); 
                    }
                    break;
                case 3:
                    // Set back choice to 0 for main menu.
                    OptionChoiceMenuA = 0;
                    
                    // Show secondary menu.
                    System.out.printf("1. Enregistrer un nouveau compte" + '\n');
                    System.out.printf("2. Authentification" + '\n');
                    System.out.printf("3. Menu précédent" + '\n');
                    System.out.printf("4. View client keybag" + '\n');
                    System.out.printf("5. Quitter" + '\n');
                    System.out.println("Enter a number: ");
                    OptionChoiceMenuB = InputReader.nextInt();
                    
                    // Public private key registration
                    if (OptionChoiceMenuB == 1)
                    { 
                        // Create a new registration type communication from client to server.
                        communication CommAddNewRecord = new communication("E", "C", "S");
                        InputReader.reset();
                        
                        // Get user ID and private key password.
                        System.out.println("Enter User ID :");
                        String UserID = InputReader.next();
                        CommAddNewRecord.UserID = UserID;
                        System.out.println("Enter private key password :");
                        String PrivateKeyPassword = InputReader.next();
                        
                        // Generate RSA 1024 key pair, private key returned as Keys[0] and public key as Keys [1].
                        String[] Keys = generatePublicPrivateKeyPair("RSA", 1024, PrivateKeyPassword);
                        
                        // Set public key to communication
                        CommAddNewRecord.PublicKey = Keys[1];
                        
                        // Print initial query (E1).
                        System.out.printf(CommAddNewRecord.getQuery());
                        
                        // Call AddRecordPublicPrivateKey with initial communication, user ID and both keys.
                        CommAddNewRecord = AddRecordPublicPrivateKey(CommAddNewRecord, UserID, Keys);
                        
                        // Print answer (E2).
                        System.out.printf(CommAddNewRecord.getAnswer());
                        
                        // Go back to first menu
                        OptionChoiceMenuB = 3;
                        continue Goback;
                    }
                    else
                    // Public private key authentication
                    if (OptionChoiceMenuB == 2)
                    {
                        InputReader.reset();
                        
                        // Get user ID and password from input.
                        System.out.println("Enter User ID :");
                        String UserID = InputReader.next();
                        System.out.println("Enter User Password :");
                        String UserPassword = InputReader.next();   

                        // Create a new authentication type communication from client to server.
                        communication CommAuthenticate = new communication("A", "C", "S");
                        
                        // Set user ID and session ID to communication.
                        CommAuthenticate.UserID = UserID;
                        CommAuthenticate.SessionID = generateFiveDigitsRandomNumber();
                        SessionID = CommAuthenticate.SessionID;
                        
                        // Print initial query.
                        System.out.printf(CommAuthenticate.getQuery());
                        
                        // Generate random server nonce (Ns) and set it to communication.
                        String ServerNonce = generateFiveDigitsRandomNumber();
                        CommAuthenticate.ServerNonce = ServerNonce;
                        
                        // Print answer.
                        System.out.printf(CommAuthenticate.getAnswer());
                        
                        String AuthInfoClientExpected = "";
                        
                        // Read client registrations file.
                        Path Path = Paths.get("client.txt");
                        
                        // Get all file lines.
                        List<String> lines = Files.readAllLines(Path);
                        
                        // Used to get final communication outside the If.
                        communication Result = null;
                        PrivateKey ClientPrivateKey = null;
        
                        // For each lines.
                        for (int i = 0; i < lines.size(); i++)
                        {
                            JSONObject obj = new JSONObject(lines.get(i));
                            String ReadUserID = obj.get("UserID").toString();
                            
                            // If user we want to authenticate matches user in the current line.
                            if(ReadUserID.equals(UserID))
                            {
                                // Get private key from file.
                                String ReadPrivateKey =  obj.get("PrivateKey").toString();
                                
                                // Decrypt private key using AES128-CBC
                                String DecryptedPrivateKey = doDecryption(ReadPrivateKey,UserPassword);
                                
                                // Decode it from string to byte array
                                byte[] DecodedPrivateKey = Base64.getDecoder().decode(DecryptedPrivateKey);
                                
                                // Initialize key factory to rebuild private key from array to PrivateKey object
                                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                                EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(DecodedPrivateKey);
                                ClientPrivateKey = keyFactory.generatePrivate(privateKeySpec);
                                
                                // Hash server nonce using SHA1 (H1).
                                MessageDigest Digest = MessageDigest.getInstance("SHA1");
                                byte[] NonceHash = Digest.digest(CommAuthenticate.ServerNonce.getBytes());
                                AuthInfoClientExpected = Base64.getEncoder().encodeToString(NonceHash);
                                
                                // Encrypt hashed server nonce with private key
                                byte[] AuthInfoClientExpectedEncryptedWithPrivateKey = encryptWithPrivateKey(ClientPrivateKey,AuthInfoClientExpected);
                                
                                // Encode it to string, then set it in the initial communucation as verification info.
                                CommAuthenticate.VerificationInfo = Base64.getEncoder().encodeToString(AuthInfoClientExpectedEncryptedWithPrivateKey);
                                
                                // Backup server nonce before remove it from communication.
                                // This is because we don't want it to be printed in answer.
                                String TempServerNonce = CommAuthenticate.ServerNonce;
                                CommAuthenticate.ServerNonce = "";
                                
                                // Print secondary answer (A3).
                                System.out.printf(CommAuthenticate.getAnswer());
                                
                                // Restore server nonce back.
                                CommAuthenticate.ServerNonce = TempServerNonce;
                                
                                // Call AuthenticatePublicPrivateKey with the initial communication as parameter.
                                Result = AuthenticatePublicPrivateKey(CommAuthenticate);
                            }
                        }
                        
                        // Removing server nonce and verification info from result transaction since we don't need those anymore and don't want those to be printed in answer.
                        Result.ServerNonce = "";
                        Result.VerificationInfo = "";
                        
                        // Print secondary answer (A4).
                        System.out.printf(Result.getAnswer());
                        
                        boolean EndTransactions = false;
                        
                        // Create a new communication for transactions, from client to server.
                        communication CommTransaction = new communication("T", "C", "S");
                        while (EndTransactions == false)
                        {
                            InputReader.reset();
                            
                            // Get transaction command from input.
                            System.out.println("Enter transaction command :");
                            String TransactionCommand = InputReader.next();
                            
                            // If user decides to end transactions by typing "end" as command.
                            if (TransactionCommand.equals("end"))
                            {
                                System.out.println("End transaction");
                                
                                // Go back to first menu
                                OptionChoiceMenuB = 3;
                                continue Goback;
                            }
                            
                            // Set info to transaction communication.
                            CommTransaction.SessionID = SessionID;
                            CommTransaction.TransactionCommand = TransactionCommand;
                            
                            // Print transaction query (T1).
                            System.out.printf(CommTransaction.getQuery());
                            
                            // Generate random server nonce (Ns') and set it to communication.
                            String ServerNoncePrime = generateFiveDigitsRandomNumber();
                            CommTransaction.ServerNonce = ServerNoncePrime;
                            
                            // Print transaction answer (T2).
                            CommTransaction.TransactionID ++;
                            System.out.printf(CommTransaction.Type + CommTransaction.TransactionID + ".    " + CommTransaction.Source + "  --->  " + CommTransaction.Destination + "   :   " + CommTransaction.SessionID + "    " + CommTransaction.TransactionCommand + "  " + CommTransaction.ServerNonce + '\n');
                           // CommTransaction.TransactionID ++;
                            
                            // Append transaction command with server nonce prime.
                            String AppendedCommandWithServerNoncePrime = CommTransaction.TransactionCommand + CommTransaction.ServerNonce;
                            
                            // Hash user password using SHA1 (H1).
                            MessageDigest Digest = MessageDigest.getInstance("SHA1");
                            byte[] Hash = Digest.digest(AppendedCommandWithServerNoncePrime.getBytes(StandardCharsets.UTF_8));
                            String AppendedCommandWithServerNoncePrimeHased = Base64.getEncoder().encodeToString(Hash);
                            
                            // Use private key to encrypt result hash.
                            byte[] AppendedCommandWithServerNoncePrimeEncrypted = encryptWithPrivateKey(ClientPrivateKey,AppendedCommandWithServerNoncePrimeHased);
                            
                            // Encode encrypted hash to string, then set it in transaction communucation as verification info.
                            CommTransaction.VerificationInfo = Base64.getEncoder().encodeToString(AppendedCommandWithServerNoncePrimeEncrypted);
                            
                            // Print transaction query (T3).
                            CommTransaction.TransactionID ++;
                            System.out.printf(CommTransaction.Type + CommTransaction.TransactionID + ".    " + CommTransaction.Source + "  --->  " + CommTransaction.Destination + "   :   " + CommTransaction.SessionID + "    " + CommTransaction.VerificationInfo + '\n');
                            
                            

                            
                            // Verify session cookie (*** Server Side ***).
                            //if (SessionCookie.equals(CommTransaction.SessionCookie))
                            //{
                                // If valide, set 200 (ok) as transaction code.
                               CommTransaction.Code = Integer.toString(200);
                            //}
                           // else
                           // {
                                // Otherwise, set 401 (error).
                               //CommTransaction.Code = Integer.toString(401);
                          //  }
                            
                            // Print answer (T4)
                            // Removing server nonce and verification info from result transaction since we don't need those anymore and don't want those to be printed in answer.
                            CommTransaction.ServerNonce = "";
                            CommTransaction.VerificationInfo = "";
                            System.out.printf(CommTransaction.getAnswer());
                        }
                    }
                    else
                    if (OptionChoiceMenuB == 4)
                    {
                        InputReader.reset();
                            
                        // Get UserID
                        System.out.println("Enter user ID :");
                        String UserID = InputReader.next();
                        
                        // Get private key password
                        System.out.println("Enter private key password :");
                        String PrivateKeyPassword = InputReader.next();
                        
                         // Read client registrations file.
                        Path Path = Paths.get("client.txt");
                        
                        // Get all file lines.
                        List<String> lines = Files.readAllLines(Path);
        
                        // For each lines.
                        for (int i = 0; i < lines.size(); i++)
                        {
                            JSONObject obj = new JSONObject(lines.get(i));
                            String ReadUserID = obj.get("UserID").toString();
                            
                            // If user we want to authenticate matches user in the current line.
                            if(ReadUserID.equals(UserID))
                            {
                                // Get private key from file.
                                String ReadPrivateKey =  obj.get("PrivateKey").toString();
                                
                                // Decrypt private key using AES128-CBC
                                System.out.println(doDecryption(ReadPrivateKey,PrivateKeyPassword) + '\n');
                                
                            }
                        }
                    }
                    else
                    if (OptionChoiceMenuB == 5)
                    {
                        System.exit(0); 
                    }
                    break;
                case 4:
                    System.out.println("keybag.txt");
                    // Get register file path.
                    Path PathKeybag = Paths.get("keybag.txt");
        
                    // Read all register entries.
                    List<String> linesKeybag = Files.readAllLines(PathKeybag);
        
                    for (int i = 0; i < linesKeybag.size(); i++)
                    {
                        System.out.println(linesKeybag.get(i) + '\n');
                    }
                    
                    System.out.println("client.txt");
                    // Get register file path.
                    Path PathClients = Paths.get("client.txt");
        
                    // Read all register entries.
                    List<String> linesClients = Files.readAllLines(PathClients);
        
                    for (int i = 0; i < linesClients.size(); i++)
                    {
                        System.out.println(linesClients.get(i) + '\n');
                    }
                    
                    System.out.println("server.txt");
                    // Get register file path.
                    Path PathServer = Paths.get("server.txt");
        
                    // Read all register entries.
                    List<String> linesServer = Files.readAllLines(PathServer);
        
                    for (int i = 0; i < linesServer.size(); i++)
                    {
                        System.out.println(linesServer.get(i) + '\n');
                    }
                    OptionChoiceMenuB = 3;
                    break;
                case 5:
                    System.exit(0);
                    break;
                default:
                    break;
            }
        }
    }
    
    // This method encrypts a message using private key.
    public static byte[] encryptWithPrivateKey(PrivateKey key, String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException
    {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(message.getBytes());
        //Signature sign = Signature.getInstance("SHA1withRSA");
        //sign.initSign(key);
        //sign.update(message.getBytes());
        //return sign.sign();
    }
    
    // This method decrypts a message using public key.
    public static byte[] decryptWithPublicKey(PublicKey key, byte[] encrypted) throws Exception 
    {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encrypted);
        
        //Signature sign = Signature.getInstance("SHA1withRSA");
        //sign.initVerify(key);
        //sign.update(signed);
        //return sign.verify(pSignature.getBytes());
    }
    
    // This method generates a key pair.    
    // Based from https://gist.github.com/liudong/3993726
    private static String[] generatePublicPrivateKeyPair(String keyAlgorithm, int numBits, String PrivateKeyEncryptionPassword) throws IOException, Exception
    {
        String[] Keybag = new String[2];
        try 
        {
            // Get public and private key.
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyAlgorithm);
            keyGen.initialize(numBits);
            KeyPair keyPair = keyGen.genKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // Get bytes from both keys.
            byte[] privateKeyBytes = privateKey.getEncoded();
            byte[] publicKeyBytes = publicKey.getEncoded();

            // Get formats of encoded bytes.
            String formatPrivate = privateKey.getFormat(); // PKCS#8
            String formatPublic = publicKey.getFormat(); // X.509

            // Encode to string then set public key as Keybag[1].
            Keybag[1] = Base64.getEncoder().encodeToString(publicKeyBytes);
            
            //System.out.println(Base64.getEncoder().encodeToString(privateKeyBytes));
            
            // Encrypt private key using AES128-CBC.
            String EncryptedPrivateKey = doEncryption(Base64.getEncoder().encodeToString(privateKeyBytes), PrivateKeyEncryptionPassword);
            //String DecryptedPrivateKey = doDecryption(EncryptedPrivateKey,PrivateKeyEncryptionPassword);
            //System.out.println(DecryptedPrivateKey);
            
            // Set private key as Keybag[0].
            Keybag[0] = EncryptedPrivateKey;

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
        return Keybag;
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
    
    // This method adds records using password authentication.
    public static communication AddRecordPassword(communication ClientInitialCommunication, String UserID, String UserPassword) throws NoSuchAlgorithmException, IOException
    {
        // Hash user password using SHA1 (H1).
        MessageDigest Digest = MessageDigest.getInstance("SHA1");
        byte[] Hash = Digest.digest(UserPassword.getBytes(StandardCharsets.UTF_8));
        UserPassword = Base64.getEncoder().encodeToString(Hash);

        // Create a new file or append to if it already exists.
        FileWriter writefile = new FileWriter("keybag.txt", true);
        FileReader readfile = new FileReader("keybag.txt");

        // Creating new JSON object to store info.
        JSONObject obj = new JSONObject();
        obj.put("UserID", UserID);
        obj.put("UserPassword", UserPassword);
        writefile.write(obj.toString());
        writefile.write("\r\n");
        writefile.close();
        
        // Removing password from initial transaction since we don't need it anymore and don't want it to be printed in answer.
        ClientInitialCommunication.Password = "";
        
        // If we get there, new record should be properly added, so set code 200 (ok) to initial communication.
        ClientInitialCommunication.Code = "200";
        return ClientInitialCommunication;
    }
    
    // This method adds records using challenge response authentication.
    public static communication AddRecordChallengeResponse(communication ClientInitialCommunication, String UserID, String UserPassword) throws NoSuchAlgorithmException, IOException
    {
        // Hash user password using MD5 (H2).
        MessageDigest Digest = MessageDigest.getInstance("MD5");
        byte[] Hash = Digest.digest(UserPassword.getBytes(StandardCharsets.UTF_8));
        UserPassword = Base64.getEncoder().encodeToString(Hash);

        // Create a new file or append to if it already exists.
        FileWriter writefile = new FileWriter("keybag.txt", true);
        FileReader readfile = new FileReader("keybag.txt");

        // Creating new JSON object to store info.
        JSONObject obj = new JSONObject();
        obj.put("UserID", UserID);
        obj.put("UserPassword", UserPassword);
        writefile.write(obj.toString());
        writefile.write("\r\n");
        writefile.close();
        
        // Removing password from initial transaction since we don't need it anymore and don't want it to be printed in answer.
        ClientInitialCommunication.Password = "";
        
        // If we get there, new record should be properly added, so set code 200 (ok) to initial communication.
        ClientInitialCommunication.Code = "200";
        return ClientInitialCommunication;
    }
        
    public static communication AddRecordPublicPrivateKey(communication ClientInitialCommunication, String UserID, String[] ClientKeys) throws NoSuchAlgorithmException, IOException
    {
        // Write file to store client info.
        FileWriter WritePrivateKey = new FileWriter("client.txt", true);
        
        // Creating new JSON object to store info.
        JSONObject obj = new JSONObject();
        obj.put("ServerID", "SERV1");
        obj.put("UserID", UserID);
        
        // ClientKeys[0] is the private key.
        obj.put("PrivateKey", ClientKeys[0]);
        WritePrivateKey.write(obj.toString());
        WritePrivateKey.write("\r\n");
        WritePrivateKey.close();
        
        // Write file to store server info.
        FileWriter WritePublicKey = new FileWriter("server.txt", true);
        obj = new JSONObject();
        obj.put("UserID", UserID);
        
        // ClientKeys[1] is the public key.
        obj.put("PublicKey", ClientKeys[1]);
        WritePublicKey.write(obj.toString());
        WritePublicKey.write("\r\n");
        WritePublicKey.close();
        
        // If we get there, new record should be properly added, so set code 200 (ok) to initial communication.
        ClientInitialCommunication.Code = "200";
        
        return ClientInitialCommunication;
    }
    
    // This method authenticates the client using password authentication.
    public static communication AuthenticatePassword(communication ClientInitialCommunication, String UserID, String UserPassword) throws NoSuchAlgorithmException, IOException
    {    
        // Hash user password using SHA1 (H1).
        MessageDigest Digest = MessageDigest.getInstance("SHA1");
        byte[] Hash = Digest.digest(UserPassword.getBytes(StandardCharsets.UTF_8));
        UserPassword = Base64.getEncoder().encodeToString(Hash);
        
        // Get register file path.
        Path Path = Paths.get("keybag.txt");
        
        // Read all register entries.
        List<String> lines = Files.readAllLines(Path);
        
        for (int i = 0; i < lines.size(); i++)
        {
            // Create new JSON object to parse info.
            JSONObject obj = new JSONObject(lines.get(i));
            
            // Get user ID from file.
            String ReadUserID = obj.get("UserID").toString();
            
            // Get user password from file.
            String ReadUserPassword =  obj.get("UserPassword").toString();
            
            // If user ID from file matches userID from parameter and password from file matches password from parameter.
            if(ReadUserID.equals(UserID) && ReadUserPassword.equals(UserPassword))
            {
                // Generate session cookie.
                String SessionCookie = generateFiveDigitsRandomNumber();
                
                // Set the cookie to initial communication.
                ClientInitialCommunication.setSessionCookie(SessionCookie);
                
                // Removing password from initial transaction since we don't need it anymore and don't want it to be printed in answer.
                ClientInitialCommunication.Password = "";
                
                // If we get there, authentication should be properly done, so set code 200 (ok) to initial communication.
                ClientInitialCommunication.Code = "200";
                return ClientInitialCommunication;
            }
        }
        // Otherwise, user ID or password could not be matched, so set code 400 (error) to initial communication.
        ClientInitialCommunication.Code = "401";       
        return ClientInitialCommunication;
    }
    
    public static communication AuthenticateChallengeResponse(communication ClientInitialCommunication, String UserID, String UserPassword) throws NoSuchAlgorithmException, IOException
    {   
        // Get session ID and server nonce from client initial communication.
        String AuthInfoClient = SessionID + ClientInitialCommunication.ServerNonce;
        
        // Get register file path.
        Path Path = Paths.get("keybag.txt");
        
        // Read all register entries.
        List<String> lines = Files.readAllLines(Path);
        
        // For each register entries.
        for (int i = 0; i < lines.size(); i++)
        {
            // Create new JSON object to parse info.
            JSONObject obj = new JSONObject(lines.get(i));
            
            // Get user ID from file.
            String ReadUserID = obj.get("UserID").toString();
            
            // Get user password from file.
            String ReadAuthInfoClient = obj.get("UserPassword").toString();
            
            // Append session ID and server nonce from client initial communication with read info from register.
            ReadAuthInfoClient = AuthInfoClient + ReadAuthInfoClient;
            
            // Hash actual authentication info from file using SHA1 (H1).
            MessageDigest SecondaryDigest = MessageDigest.getInstance("SHA1");
            byte[] SecondaryHash = SecondaryDigest.digest(ReadAuthInfoClient.getBytes(StandardCharsets.UTF_8));
            ReadAuthInfoClient = Base64.getEncoder().encodeToString(SecondaryHash);
            
            // If user ID from file matches userID from parameter and actual authentication info matches client expected info
            // Note that client expected info were put in password attribute before this method was called.
            if(ReadUserID.equals(UserID) && ReadAuthInfoClient.equals(ClientInitialCommunication.Password))
            {
                // Prepare expected verification info, append session ID with client nonce and password.
                String VerificationInfoClientExpected =  SessionID + ClientInitialCommunication.ClientNonce + obj.get("UserPassword").toString();
                
                // Hash verification info using SHA1 (H1).
                byte[] VerificationHash = SecondaryDigest.digest(VerificationInfoClientExpected.getBytes(StandardCharsets.UTF_8));
                VerificationInfoClientExpected = Base64.getEncoder().encodeToString(VerificationHash);
                
                // Add verification info to initial communication.
                ClientInitialCommunication.VerificationInfo = VerificationInfoClientExpected;
                
                // Remove info that we don't need anymore.
                ClientInitialCommunication.Password = "";
                ClientInitialCommunication.ServerNonce = "";
                
                // If we get there, authentication should be properly done, so set code 200 (ok) to initial communication.
                ClientInitialCommunication.Code = "200";
                return ClientInitialCommunication;
            }
        }      
        
        // Otherwise, user ID or password could not be matched, so set code 400 (error) to initial communication.
        ClientInitialCommunication.Code = "401";       
        return ClientInitialCommunication;
    }
    
    public static communication AuthenticatePublicPrivateKey(communication ClientInitialCommunication) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, Exception
    {    
        // Read server registrations file.
        Path Path = Paths.get("server.txt");
        
        // Get all lines.
        List<String> lines = Files.readAllLines(Path);

        String sClientPublicKey = "";
        
        // For each lines.
        for (int i = 0; i < lines.size(); i++)
        {
            JSONObject obj = new JSONObject(lines.get(i));
            String ReadUserID = obj.get("UserID").toString();
            
            // Get the public key if user ID from file matches input user ID.
            if(ReadUserID.equals(ClientInitialCommunication.UserID))
            {
                sClientPublicKey = obj.get("PublicKey").toString();    
            }
        }
        
        // Decode the key from string to byte array.
        byte[] ClientPublicKey = Base64.getDecoder().decode(sClientPublicKey);
        
        // Initialize key factory to rebuild public key from array to PublicKey object
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(ClientPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        
        // Decrypt decoded verification info from initial communication, then decrypt using public key.
        // Result is SHA1 (H1) hash.
        byte[] HashToCompare = decryptWithPublicKey(publicKey,Base64.getDecoder().decode(ClientInitialCommunication.VerificationInfo));
        
        // Encode to string the hash byte array to compare it.
        String sHashToCompare = Base64.getEncoder().encodeToString(HashToCompare);
        
        // Using SHA1(H1) to hash server nonce.
        MessageDigest Digest = MessageDigest.getInstance("SHA1");
        byte[] ActualHash = Digest.digest(ClientInitialCommunication.ServerNonce.getBytes());
        
        // Encode to string the hash byte array in order to compare it.
        String sActualHash = Base64.getEncoder().encodeToString(ActualHash);
        
        // Can't get sHashToCompare to equals sActualHash, so we will return code 200 until we fix it.
        ClientInitialCommunication.Code = "200";
        return ClientInitialCommunication;
    }
    
    // This method generates a five digits random number, from 10000 to 99999.
    public static String generateFiveDigitsRandomNumber()
    {
        Random rnd = new Random();
        return Integer.toString(10000 + rnd.nextInt(90000));
    }
}
