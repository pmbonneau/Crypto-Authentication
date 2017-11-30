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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Scanner;
import jsonParser.JSONObject;

/**
 *
 * @author root
 */
public class main {

    /**
     * @param args the command line arguments
     */
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
                    AddRecord();
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
    
    public static void AddRecord() throws NoSuchAlgorithmException, IOException
    {
        Scanner InputReader = new Scanner(System.in);  
        System.out.println("Enter User ID :");
        String UserID = InputReader.nextLine();
        System.out.println("Enter User Password :");
        String UserPassword = InputReader.nextLine();

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
    }
}
