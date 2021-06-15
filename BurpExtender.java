package burp;
import java.io.PrintWriter;
import java.net.URL;
import java.util.List;
public class BurpExtender implements IBurpExtender, IHttpListener, IProxyListener
{
    private IExtensionHelpers helpers;
    PrintWriter stdout;
    @Override
	public void registerExtenderCallbacks (IBurpExtenderCallbacks callbacks){
// set our extension name
        callbacks.setExtensionName("Tutorial extension");
        
        // obtain our output and error streams
        stdout = new PrintWriter(callbacks.getStdout(), true);
        PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
        
        // write a message to our output stream
        stdout.println("Hello output");

        helpers = callbacks.getHelpers();
        callbacks.registerHttpListener(this);
    }
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo){
        if(messageIsRequest){
            IHttpService httpService = messageInfo.getHttpService();

            String host = httpService.getHost();
            if(host != null){
                stdout.println(host);
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
            stdout.println("I was here");
            String request = new String(messageInfo.getRequest());
            String messageBody = request.substring(rqInfo.getBodyOffset());
            byte[] updateMessage = helpers.buildHttpMessage(headers, messageBody.getBytes());
            messageInfo.setRequest(updateMessage);
        }
    }
}