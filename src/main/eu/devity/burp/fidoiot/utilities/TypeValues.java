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

    public static String signExclInst = "<h3>Signature Exclusion Attack</h3>\n<ul>\n<li>Select Signature Exclusion attack in Attack Dropdown</li>\n<li>Sub Attack is automatically selected</li>\n<li>Press Attack</li>\n</ul>";
    
    public static String keyConfInst = "<h3>Key Confusion Attack</h3>\n<ul>\n<li>Select Key Confusion attack in Attack Dropdown</li>\n<li>Sub Attack is automatically selected</li>\n<li>Add Certificate in Certificate Tab</li>\n<li>Select certificate from the dropdown</li>\n<li>Press Attack</li>\n</ul> ";
    
}
