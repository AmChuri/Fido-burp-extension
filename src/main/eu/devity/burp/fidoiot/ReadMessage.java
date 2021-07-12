package burp;
import java.io.PrintWriter;


public class ReadMessage implements  IHttpListener {

    private final IExtensionHelpers helpers;
    PrintWriter stdout;

    public ReadMessage(IBurpExtenderCallbacks callbacks) {
        stdout.println("init");
        this.helpers = callbacks.getHelpers();
    }


    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo){
        stdout.println("hey");
        if(messageIsRequest){
            IHttpService httpService = messageInfo.getHttpService();

            String host = httpService.getHost();
            int port = httpService.getPort();
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

}