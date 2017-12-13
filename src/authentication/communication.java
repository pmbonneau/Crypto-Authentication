/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package authentication;

import java.util.Scanner;

/**
 *
 * @author Pierre-Marc
 */
public class communication 
{
    String Type;
    int TransactionID = 0;
    String Source;
    String Destination;
    
    String SessionID = "";
    String SessionCookie = "";
    String UserID = "";
    String Password = "";
    String Code = "";
    String TransactionCommand = "";
    String ServerNonce = "";
    String ClientNonce = "";
    String VerificationInfo = "";
    String PublicKey = "";
    public communication(String pType, String pSource, String pDestination)
    {
        Type = pType;
        Source = pSource;
        Destination = pDestination;       
    }
    
    public void setCode(String pCode)
    {
        Code = pCode;
    }
    
    public void setSessionID(String pSessionID)
    {
        SessionID = pSessionID;
    }
    
    public void setSessionCookie(String pSessionCookie)
    {
        SessionCookie = pSessionCookie;
    }
    
    public void setServerNonce(String pServerNonce)
    {
        ServerNonce = pServerNonce;
    }
    
    public void setVerificationInfo(String pVerificationInfo)
    {
        VerificationInfo = pVerificationInfo;
    }
    
    public void setPublicKey(String pPublicKey)
    {
        PublicKey = pPublicKey;
    }
    
    public void setClientNonce(String pClientNonce)
    {
        ClientNonce = pClientNonce;
    }
    
    public void setTransactionCommand(String pTransactionCommand)
    {
        TransactionCommand = pTransactionCommand;
    }
    
    public String getQuery()
    {
        Scanner InputReader = new Scanner(System.in);
        System.out.printf("Do you want to modify the message ? (y for yes or n to leave it as-is." + '\n');
        if (InputReader.next().equals("y"))
        {
            TransactionID++;
            System.out.printf("Enter SessionID (type '$' to leave it unchanged) :" + '\n');
            if (!InputReader.next().equals("$"))
            {
                SessionID = InputReader.next();
            }
            System.out.printf("Enter UserID (type '$' to leave it unchanged) :" + '\n');
            if (!InputReader.next().equals("$"))
            {
                UserID = InputReader.next();
            }
            System.out.printf("Enter Password (type '$' to leave it unchanged) :" + '\n');
            if (!InputReader.next().equals("$"))
            {
                Password = InputReader.next();
            }
            System.out.printf("Enter Public Key (type '$' to leave it unchanged) :" + '\n');
            if (!InputReader.next().equals("$"))
            {
                PublicKey = InputReader.next();
            }
            System.out.printf("Enter Transaction Command (type '$' to leave it unchanged) :" + '\n');
            if (!InputReader.next().equals("$"))
            {
                TransactionCommand = InputReader.next();
            }
            System.out.printf("Enter Session Cookie (type '$' to leave it unchanged) :" + '\n');
            if (!InputReader.next().equals("$"))
            {
                SessionCookie = InputReader.next();
            }
            System.out.printf("Enter Client Nonce (type '$' to leave it unchanged) :" + '\n');
            if (!InputReader.next().equals("$"))
            {
                ClientNonce = InputReader.next();
            }
            System.out.printf("Enter Server Nonce (type '$' to leave it unchanged) :" + '\n');
            if (!InputReader.next().equals("$"))
            {
                ClientNonce = InputReader.next();
            }
        return Type + TransactionID + ".    " + Source + "  --->  " + Destination + "   :   " + SessionID + " " + UserID + " " + Password + " " + PublicKey + " " + TransactionCommand + " " + SessionCookie + " " + ClientNonce + '\n';
        }
        TransactionID++;
        return Type + TransactionID + ".    " + Source + "  --->  " + Destination + "   :   " + SessionID + " " + UserID + " " + Password + " " + PublicKey + " " + TransactionCommand + " " + SessionCookie + " " + ClientNonce + '\n';
    }
    
    public String getAnswer()
    {
        Scanner InputReader = new Scanner(System.in);
        System.out.printf("Do you want to modify the message ? (y for yes or n to leave it as-is." + '\n');
        if (InputReader.next().equals("y"))
        {
            TransactionID++;
            System.out.printf("Enter SessionID (type '$' to leave it unchanged) :" + '\n');
            if (!InputReader.next().equals("$"))
            {
                SessionID = InputReader.next();
            }
            System.out.printf("Enter UserID (type '$' to leave it unchanged) :" + '\n');
            if (!InputReader.next().equals("$"))
            {
                UserID = InputReader.next();
            }
            System.out.printf("Enter Password (type '$' to leave it unchanged) :" + '\n');
            if (!InputReader.next().equals("$"))
            {
                Password = InputReader.next();
            }
            System.out.printf("Enter Public Key (type '$' to leave it unchanged) :" + '\n');
            if (!InputReader.next().equals("$"))
            {
                PublicKey = InputReader.next();
            }
            System.out.printf("Enter Transaction Command (type '$' to leave it unchanged) :" + '\n');
            if (!InputReader.next().equals("$"))
            {
                TransactionCommand = InputReader.next();
            }
            System.out.printf("Enter Session Cookie (type '$' to leave it unchanged) :" + '\n');
            if (!InputReader.next().equals("$"))
            {
                SessionCookie = InputReader.next();
            }
            System.out.printf("Enter Client Nonce (type '$' to leave it unchanged) :" + '\n');
            if (!InputReader.next().equals("$"))
            {
                ClientNonce = InputReader.next();
            }
            System.out.printf("Enter Server Nonce (type '$' to leave it unchanged) :" + '\n');
            if (!InputReader.next().equals("$"))
            {
                ClientNonce = InputReader.next();
            }
            return Type + TransactionID + ".    " + Destination + "  --->  " + Source + "   :   " + SessionID + " " + Code + " " + Password + " " + VerificationInfo + " " + SessionCookie + " " + ServerNonce + '\n';
        }
        TransactionID++;
        return Type + TransactionID + ".    " + Destination + "  --->  " + Source + "   :   " + SessionID + " " + Code + " " + Password + " " + VerificationInfo + " " + SessionCookie + " " + ServerNonce + '\n';
    }
}
