/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package authentication;

import java.util.Scanner;

/**
 *
 * @author root
 */
public class main {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) 
    {
        System.out.printf("1. Mot de passe" + '\n');
        System.out.printf("2. Ms-CHAP-v2" + '\n');
        System.out.printf("3. UAF" + '\n');
        System.out.printf("4. Quitter" + '\n');
        
        int OptionChoice;
        try (Scanner InputReader = new Scanner(System.in)) 
        {
            System.out.println("Enter a number: ");
            OptionChoice = InputReader.nextInt();
        } 
        
        switch (OptionChoice) {
            case 1:
                System.out.println("1");
                break;
            case 2:
                System.out.println("2");
                break;
            case 3:
                System.out.println("3");
                break;
            case 4:
                System.out.println("4");
                break;
            default:
                break;
        }
    }
    
}
