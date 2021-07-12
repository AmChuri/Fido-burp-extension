package burp;
import java.io.PrintWriter;
import java.net.URL;
import java.util.List;
import java.text.SimpleDateFormat;
import java.util.Calendar;
public class BurpExtender implements IBurpExtender, IExtensionStateListener
{
    private IExtensionHelpers helpers;

    PrintWriter stdout;

	public void registerExtenderCallbacks (IBurpExtenderCallbacks callbacks){
// set our extension name
        callbacks.setExtensionName("Tutorial extension");
        // obtain our output and error streams
        stdout = new PrintWriter(callbacks.getStdout(), true);
        PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
        // Get current time
        Calendar calObj = Calendar.getInstance();
        SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");
        String time = dateFormat.format(calObj.getTime());
        stdout.println("+---------------------------------------------------------+");
        stdout.println("|                  BURP Extension for FIDO                |");
        stdout.println("|                     Version 0.0.0                       |");
        stdout.println("|                   Started @ " + time + "                    |");
        stdout.println("+---------------------------------------------------------+");
        

        
        // write a message to our output stream
        stdout.println("Hello output");

        helpers = callbacks.getHelpers();
//        callbacks.registerProxyListener(this);
//        callbacks.registerHttpListener(this);
        ReadMessage readMessage = new ReadMessage(callbacks);
        callbacks.registerHttpListener(readMessage);

    }
    /*
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo){
        if(messageIsRequest){
            IHttpService httpService = messageInfo.getHttpService();

            String host = httpService.getHost();
            int port = httpService.getPort();
            List test = helpers.analyzeRequest(messageInfo).getParameters();
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            stdout.println("Parameters");
            //stdout.println(requestInfo.getParameters());
            for (IParameter param : requestInfo.getParameters()) {
                stdout.println(param.getName());
                stdout.println(param.getValue());
            }


            if(host != null){
                stdout.println(host);
                stdout.println(helpers.analyzeRequest(messageInfo).getUrl());
            }
        }
    }

     */
/*
    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message){
        stdout.println("Entered message request");
        stdout.println(messageIsRequest);
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
 */

    @Override
    public void extensionUnloaded() {
        stdout.println("EXTENSION_UNLOADED");
    }
}