package burp;

/**
 * Information About Type of attacks that can be performed on the message
 * Signature Exclusion - 0
 * Key Confusion - 1
 * SSRF - 2
 */
public class CustomMessageInfo {

    private final IExtensionHelpers helpers;

    public CustomMessageInfo(IBurpExtenderCallbacks callbacks) {
        this.helpers = callbacks.getHelpers();
    }


}