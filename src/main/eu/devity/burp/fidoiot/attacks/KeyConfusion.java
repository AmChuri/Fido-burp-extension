package src.main.eu.devity.burp.fidoiot.attacks;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IHttpService;
import java.io.PrintWriter;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class KeyConfusion {


    public KeyConfusion(IBurpExtenderCallbacks callbacks, IHttpRequestResponse message){
    
    }

    public byte[] hmac256SHAgen(byte[] secretKey, byte[] message){
        byte[] hmacSha256 = null;
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "HmacSHA256");
      mac.init(secretKeySpec);
      hmacSha256 = mac.doFinal(message);
    } catch (Exception e) {
      throw new RuntimeException("Failed to calculate hmac-sha256", e);
    }
    return hmacSha256;
    }
    
}
