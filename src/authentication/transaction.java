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
public class transaction 
{
    String Type;
    int TransactionID;
    String Source;
    String Destination;
    
    String SessionID = "";
    String UserID = "";
    String Password = "";
    String Code = "";
    public transaction(String pType, int pTransactionID, String pSource, String pDestination)
    {
        Type = pType;
        TransactionID = pTransactionID;
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
    
    public String getQuery()
    {
        return Type + TransactionID + ".    " + Source + "  --->  " + Destination + "   :   " + SessionID + " " + UserID + " " + Password + '\n';
    }
    
    public String getAnswer()
    {
        return Type + (TransactionID + 1) + ".    " + Destination + "  --->  " + Source + "   :   " + SessionID + " " + Code + '\n';
    }
}
