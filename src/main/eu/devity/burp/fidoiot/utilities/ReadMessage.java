package burp;
import java.io.PrintWriter;
import java.net.URL;
import java.util.List;

/**
 * Class to capture request to read the content of the request to identify the type of attack that can be
 * immplemented
 */
public class ReadMessage implements  IHttpListener,IProxyListener {

    private final IExtensionHelpers helpers;
    private static PrintWriter stdout;

    public ReadMessage(IBurpExtenderCallbacks callbacks) {
        this.helpers = callbacks.getHelpers();
        // obtain our output
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
    }


    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo){
        if(messageIsRequest){
            IHttpService httpService = messageInfo.getHttpService();

            String host = httpService.getHost();
            int port = httpService.getPort();
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            //private byte[] test = null;
            String nullSG[][] = {{"sg"},{"0","0"}};
            for (IParameter param : requestInfo.getParameters()) {
                if(param.getName().matches("sg")){
                    messageInfo.setComment("Signature excl possible");
                    messageInfo.setHighlight("red");
                    stdout.println("Can be attacked");
                    stdout.println(requestInfo.getUrl());
                    stdout.println(param.getName());
                    stdout.println(param.getValue());
                    stdout.println("======xxx=====");
                }
            }
        }
    }


    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message){
        if(messageIsRequest){
            IHttpRequestResponse messageInfo = message.getMessageInfo();
            IRequestInfo rqInfo = helpers.analyzeRequest(messageInfo);
            List headers = rqInfo.getHeaders();
            headers.add("Test: NewHostTest");
            String request = new String(messageInfo.getRequest());
            String messageBody = request.substring(rqInfo.getBodyOffset());
            byte[] updateMessage = helpers.buildHttpMessage(headers, messageBody.getBytes());
            messageInfo.setRequest(updateMessage);
        }
    }


}