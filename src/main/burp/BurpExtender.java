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
        callbacks.setExtensionName("FIDOIoT extension");
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


        //helpers = callbacks.getHelpers();
        //callbacks.registerProxyListener(this);
        //callbacks.registerHttpListener(this);
       ReadMessage readMessage = new ReadMessage(callbacks);
        callbacks.registerHttpListener(readMessage);
        callbacks.registerProxyListener(readMessage);

//        UITab uiTab = new UITab(callbacks);

    }

    @Override
    public void extensionUnloaded() {
        stdout.println("EXTENSION_UNLOADED");
    }


}