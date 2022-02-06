package src.main.eu.devity.burp.fidoiot.utilities;

public class TypeValues {
/**
 *  Class for all constant Values
 */

    public enum ATTACKS {
        SIGNATUREEXCL,
        KEYCONFUSION,
        SSRF
      }

    public static String signExclSubAtk[] = {"Signature Exclusion"};

    public static String keyConfSubAtk[] = {"Key Confusion"};

    public static String ssrfSubAtk[] = {"SSRF", "Host Header SSRF", "Protocol Smuggling SSRF"};
    
}
