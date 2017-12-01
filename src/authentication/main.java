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
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException 
    {      
        int OptionChoiceMenuA = 0;
        int OptionChoiceMenuB = 3;
        int TransactionID = 0;
        int SessionID = 100;
        
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
                        transaction Result = AddRecord(TransactionID);
                        System.out.printf(Result.getAnswer());
                        TransactionID = TransactionID + 2;
                    }
                    else
                    if (OptionChoiceMenuB == 2)
                    {
                        transaction Result = Authenticate(TransactionID, Integer.toString(SessionID));
                        System.out.printf(Result.getAnswer());
                        TransactionID = TransactionID + 2;
                        SessionID++;
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
    
    public static transaction AddRecord(int TransactionNumber) throws NoSuchAlgorithmException, IOException
    {
        Scanner InputReader = new Scanner(System.in);  
        System.out.println("Enter User ID :");
        String UserID = InputReader.nextLine();
        System.out.println("Enter User Password :");
        String UserPassword = InputReader.nextLine();
        
        transaction TrAddNewRecord = new transaction("E", TransactionNumber, "C", "S");
        TrAddNewRecord.UserID = UserID;
        TrAddNewRecord.Password = UserPassword;
        System.out.printf(TrAddNewRecord.getQuery());

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
        TrAddNewRecord.Code = "200";
        return TrAddNewRecord;
    }
    
    public static transaction Authenticate(int TransactionNumber, String SessionID) throws NoSuchAlgorithmException, IOException
    {
        Scanner InputReader = new Scanner(System.in);  
        System.out.println("Enter User ID :");
        String UserID = InputReader.nextLine();
        System.out.println("Enter User Password :");
        String UserPassword = InputReader.nextLine();
        
        transaction TrAuthenticate = new transaction("A", TransactionNumber, "C", "S");
        TrAuthenticate.UserID = UserID;
        TrAuthenticate.Password = UserPassword;
        TrAuthenticate.SessionID = SessionID;
        System.out.printf(TrAuthenticate.getQuery());
        
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
            if(ReadUserID == UserID && ReadUserPassword == UserPassword)
            {
                TrAuthenticate.Code = "200";
                return TrAuthenticate;
            }
        }
        
        TrAuthenticate.Code = "401";
        
        return TrAuthenticate;
    }
}
