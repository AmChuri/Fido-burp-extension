package burp;
import java.io.PrintWriter;
import java.net.URL;
import java.util.List;

/**
 * Read Content of the request
 */
public class MessageContent {

    private final IParameter msgParameters;

    /**
     * Parameters to check if signature exclusion is possbile on request
     * sg should be present and not empty
     */
    private String[] signatureExclVar = {"sg", "pk"};


    public MessageContent(IParameter parameter){
        this.msgParameters = parameter;
    }

//    public boolean checkContent(){
//
//    }





}