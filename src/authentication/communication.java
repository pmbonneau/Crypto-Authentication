/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package authentication;

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
        TransactionID++;
        return Type + TransactionID + ".    " + Source + "  --->  " + Destination + "   :   " + SessionID + " " + UserID + " " + Password + " " + PublicKey + " " + SessionCookie + " " + TransactionCommand + " " + ClientNonce + '\n';
    }
    
    public String getAnswer()
    {
        TransactionID++;
        return Type + TransactionID + ".    " + Destination + "  --->  " + Source + "   :   " + SessionID + " " + Code + " " + Password + " " + VerificationInfo + " " + SessionCookie + " " + ServerNonce + '\n';
    }
}
