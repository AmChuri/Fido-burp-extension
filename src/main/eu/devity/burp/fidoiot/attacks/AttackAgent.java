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



public class AttackAgent {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private IResponseInfo responseInfo;
    private IHttpService httpService;
    private static final Logger loggerInstance = Logger.getInstance();

    AttackExecutor attackRequestExecutor;

    public AttackAgent(IBurpExtenderCallbacks callbacks, IHttpRequestResponse message) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.httpService = message.getHttpService();

    }


    public void sendAttackReq(byte[] updateMessage, IHttpService tempService) {
        loggerInstance.log(getClass(), "Executing Attack", Logger.LogLevel.INFO);
        this.httpService = tempService;
        attackRequestExecutor = new AttackExecutor(updateMessage);
        attackRequestExecutor.execute();
    }





    /**
     * Java Swing worker to execute attack in the background
     */

    private class AttackExecutor extends SwingWorker<IHttpRequestResponse, Integer> {
        private byte[] attackRequest;

        AttackExecutor(byte[] attackRequest) {
            this.attackRequest = attackRequest;
            loggerInstance.log(AttackAgent.class, "Failed to get request result: ",
                        Logger.LogLevel.INFO);
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
                loggerInstance.log(AttackAgent.class, "Failed to get request result: " + e.getMessage(),
                        Logger.LogLevel.ERROR);
                return;
            }
            // getting message from the response
            String temp = new String(requestResponse.getResponse());
            responseInfo = helpers.analyzeResponse(requestResponse.getResponse());
            String messageBody = temp.substring(responseInfo.getBodyOffset());
            loggerInstance.log(getClass(), "Attack Performed: Response" + messageBody, Logger.LogLevel.DEBUG);
        }
    }

}