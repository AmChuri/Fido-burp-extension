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

    public static String signExclSubAtk[] = {"0 Value", "NULL", "None", "Remove signature", "ALL"};

    public static String keyConfSubAtk[] = {"PEM Format Key", "String Format", "No Header Footer", "ALL"};

    public static String ssrfSubAtk[] = {"SSRF", "Host Header SSRF", "X-Host Header SSRF", "ALL"};

    public static String signatureType[]={"SHA1withRSA", "SHA256withRSA", "SHA384withRSA", "SHA512withRSA",
            "NONEwithECDSA","SHA1withECDSA","SHA256withECDSA","SHA384withECDSA", "SHA512withECDSA"};

    public static String signExclInst = "<h3>Signature Exclusion Attack</h3>\n<ul>\n<li>Select Signature Exclusion attack in Attack Dropdown</li>\n<li>Sub Attack is automatically selected</li>\n<li>Press Attack</li>\n</ul>";
    
    public static String keyConfInst = "<h3>Key Confusion Attack</h3>\n<ul>\n<li>Select Key Confusion attack in Attack Dropdown</li>\n<li>Sub Attack is automatically selected</li>\n<li>Add Certificate in Certificate Tab</li>\n<li>Select certificate from the dropdown</li>\n<li>Press Attack</li>\n</ul> ";
    
    public static String ssrfInst = "<h3>Server Side Request Forgery</h3>\n<ul>\n<li>Select SSRF in Attack Dropdown</li>\n<li>Select Sub Attack is Sub attack dropdown</li>\n</ul>";
  
    public static String ssrfSubInst = "<h3>Server Side Request Forgery</h3>\n<ul>\n<li>Select SSRF in Attack Dropdown</li>\n<li>Select SSRF is Sub attack dropdown</li>\n<li>Analyze to check if SSRF attack is possible</li>\n<li>Select Certificate from List</li>\n<li>Fill arbitary domain value in Input</li>\n<li>Set Proxy Values</li>\n <li>Click Attack</li>\n</ul> ";

    public static String ssrfHostHeaderInst = "<h3>Host Header SSRF</h3>\n<ul>\n<li>Select SSRF in Attack Dropdown</li>\n<li>Select Host Header SSRF is Sub attack dropdown</li>\n<li>Fill Host value in Input</li>\n<li>Set Proxy Values</li>\n<li>Click Attack</li>\n</ul>";


    public static String ssrfProtocolSmugglingInst = "<h3>Protocol Smuggling SSRF</h3>\n<ul>\n<li>Select SSRF in Attack Dropdown</li>\n<li>Select Host Header SSRF is Sub attack dropdown</li>\n<li>Fill Complete domain value in Input</li>\n<li>Set Proxy Values</li>\n<li>Click Attack</li>\n</ul>";
  

    public static String analysisHeader = "<h3>Analysis</h3>";

    public static String analysisSig = "<ul>\n<li>Message Body Contains Signature</li>\n<li>Signature Exclusion and Key Confusion Attacks are possible</li>\n</ul> ";

    public static String analysisSSRF = "<ul>\n<li>URL values are observed</li>\n<li>SSRF Attacks are possible</li>\n</ul> ";

    public static String analysisNoAttack = "<ul>\n<li>No Attack Seems Possible</li>\n</ul> ";


    public static String signExclAttackParam[] = {"0", "null", "None", "remove"};

    public static String keyConfAttackParam[] = {"PEM", "String", "NoHeadFoot"};
    
    public static String ssrfAttackParam[] = {"bodySigning", "Host", "X-Host"};

    




  }
