package burp;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IHttpService;
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
import java.net.MalformedURLException;

public class SSRFAttack {

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

    public SSRFAttack(IBurpExtenderCallbacks callbacks, IHttpRequestResponse message){

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.requestResponse = message;
        this.requestInfo = helpers.analyzeRequest(message);
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.httpService = message.getHttpService();
    }

    public void hostheaderAttack(String modText, boolean isProxy, String proxyDNS, int proxyPort){
        loggerInstance.log(getClass(), "Executing Host Header SSRF Attack"  , Logger.LogLevel.INFO);
        List<String> headers = requestInfo.getHeaders();
        String request = new String(requestResponse.getRequest());
        String messageBody = request.substring(requestInfo.getBodyOffset());
        int i = 0;
        int replaceid = 0;
        for(String s: headers){
            if(s.contains("Host")){
                replaceid = i;
            }
            i++;
        }

        List<String> items = Arrays.asList(modText.split("\\s*,\\s*"));
        i = 0;
        // if more than one host are forwarded than enter for loop
        if(items.size() > 1) {
            for (String s : items) {
                if(i == 1) {
                    headers.set(replaceid, s);
                } else{
                    headers.add(replaceid+i, s);
                }
                i++;
            }
        } else{
            headers.set(replaceid,modText);
        }
        loggerInstance.log(getClass(), headers.toString()  , Logger.LogLevel.INFO);

        if(isProxy){
            this.httpService = helpers.buildHttpService(proxyDNS,proxyPort,this.httpService.getProtocol());
        }
        updateMessage = helpers.buildHttpMessage(headers, messageBody.getBytes());
        this.sendAttackReq();
    }



    public void protcolSmugAttack(String modText, boolean isProxy, String proxyDNS, int proxyPort){
        loggerInstance.log(getClass(), "Executing Protocol Smuggling SSRF Attack"  , Logger.LogLevel.INFO);
        URL temp = requestInfo.getUrl();
        List<String> headers = requestInfo.getHeaders();
        String request = new String(requestResponse.getRequest());
        String messageBody = request.substring(requestInfo.getBodyOffset());

        loggerInstance.log(getClass(), modText , Logger.LogLevel.INFO);
        loggerInstance.log(getClass(), messageBody , Logger.LogLevel.INFO);
//        IHttpService httpService = requestResponse.getHttpService();
        // for proxy set http service
        // hard coded dns and port need to take value from the user
        if(isProxy){
            this.httpService = helpers.buildHttpService(proxyDNS,proxyPort,this.httpService.getProtocol());
        }
        loggerInstance.log(getClass(), "Header"  , Logger.LogLevel.INFO);
        int i = 0;
        headers.set(0, "POST /test HTTP/1.1");
        for(String s: headers){
            loggerInstance.log(getClass(), s  , Logger.LogLevel.INFO);
            i++;
        }

        // protocol smuggling test

        URL urlToTest;
        byte[] test;
        try {
            urlToTest = new URL(this.httpService.getProtocol(), this.httpService.getHost(), this.httpService.getPort(), "/test");
            test = helpers.buildHttpRequest(urlToTest);
            String s1 = new String(test, StandardCharsets.UTF_8);
            loggerInstance.log(getClass(), s1  , Logger.LogLevel.INFO);
        } catch (MalformedURLException ex) {
            loggerInstance.log(getClass(), "MalformedURLException"  , Logger.LogLevel.ERROR);
        }


        loggerInstance.log(getClass(), temp.toString() , Logger.LogLevel.INFO);
//        updateMessage = helpers.buildHttpMessage(headers, messageBody.getBytes()); // uses this.current message body
        updateMessage = helpers.buildHttpMessage(headers, modText.getBytes());
        this.sendAttackReq();

    }

    public void sendAttackReq(){
        loggerInstance.log(getClass(), "Executing SSRF Attack in the Background"  , Logger.LogLevel.INFO);
        AttackExecutor attackRequestExecutor = new AttackExecutor(updateMessage);
        attackRequestExecutor.execute();
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
//            return callbacks.makeHttpRequest("127.0.0.1",8055,false, this.attackRequest);
        }

        @Override
        // Add response to response list, add new entry to attacker result
        // window table and update process bar
        protected void done() {
            IHttpRequestResponse requestResponse;
            try {
                requestResponse = get();
            } catch (InterruptedException | ExecutionException e) {
                loggerInstance.log(SSRFAttack.class, "Failed to get request result: " + e.getMessage(), Logger.LogLevel.ERROR);
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