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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.Scanner;
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
    
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException 
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
                        
                        
                        //String ClientNonce = generateFiveDigitsRandomNumber();
                        //CommAuthenticate.ClientNonce = ClientNonce;
                        //CommAuthenticate.UserID = "";
                        communication Result = AuthenticateChallengeResponse(CommAuthenticate, UserID, UserPassword);
                        System.out.printf(CommAuthenticate.getQuery());
                        System.out.printf(Result.getAnswer());
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
                    break;
                case 4:
                    System.out.println("4");
                    break;
                default:
                    break;
            }
        }
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
            String ReadAuthInfoClient =  obj.get("UserPassword").toString();
            ReadAuthInfoClient = AuthInfoClient + ReadAuthInfoClient;
            MessageDigest SecondaryDigest = MessageDigest.getInstance("SHA1");
            byte[] SecondaryHash = SecondaryDigest.digest(ReadAuthInfoClient.getBytes(StandardCharsets.UTF_8));
            ReadAuthInfoClient = Base64.getEncoder().encodeToString(SecondaryHash);
            if(ReadUserID.equals(UserID) && ReadAuthInfoClient.equals(ClientInitialCommunication.Password))
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
    
    public static String generateFiveDigitsRandomNumber()
    {
        Random rnd = new Random();
        return Integer.toString(10000 + rnd.nextInt(90000));
    }
}
