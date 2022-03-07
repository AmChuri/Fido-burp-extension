package src.main.eu.devity.burp.fidoiot.utilities;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import src.main.eu.devity.burp.fidoiot.utilities.custom.Certificate;

public class JsonParser {

    String userDir;
    Certificate[] tempList;
    private static final Logger loggerInstance = Logger.getInstance();
    private static final String certificateFilePath = System.getProperty("user.home") + "/.fido/certificate.json";

    public JsonParser() {
        userDir =  System.getProperty("user.home");

        tempList = new Certificate[getCertCount()];
        // populateCertificate();
        readCertFile();
    }


    public void readCertFile() {
        File certFile = new File(certificateFilePath);

        if (!certFile.exists()) {
            loggerInstance.log(getClass(), "Config file does not exist!", Logger.LogLevel.ERROR);
            return;
        }

        if (!certFile.isDirectory() && certFile.canRead()) {

            JSONParser jsonParser = new JSONParser();

            try {
                FileReader certFileReader = new FileReader(certFile);
                JSONObject certObj = (JSONObject) jsonParser.parse(certFileReader);
                JSONArray array = (JSONArray) certObj.get("list");
                for (int i = 0; i < array.size(); i++) {
                    JSONObject obj = (JSONObject) array.get(i);
                    String name = (String) obj.get("name");
                    String filePath = (String) obj.get("file");
                    String type = (String) obj.get("type");
                    populateCertificate(i, filePath,name, type);
                  }

            } catch ( Exception e) {
                loggerInstance.log(getClass(), "Config file can not be read!\n" + e.toString(), Logger.LogLevel.ERROR);
            }
        } else {
            loggerInstance.log(getClass(), "The config file is not readable or a directory: " + certificateFilePath, Logger.LogLevel.ERROR);
        }
        
    }

    public void populateCertificate(int id, String filePath, String name, String type){
        tempList[id] = new Certificate(filePath, name, type);
        // tempList[0] = new Certificate("/home/amey/thesis/keys/ocs/type22pubkey.pem", "Type 22 Public Key", "EC");
        // tempList[1] = new Certificate("/home/amey/thesis/keys/ocs/type22privec256.pem", "Type 22 Private key", "EC");
        // tempList[2] = new Certificate("/home/amey/thesis/keys/ocs/privec256.pem", "Custom EC 256", "EC");
        // tempList[3] = new Certificate("/home/amey/thesis/keys/ocs/privec384.pem", "Custom EC 384", "EC");
        // tempList[3] = new Certificate("/home/amey/thesis/keys/ocs/privrsa2048-owner.pem", "Custom RSA 2048", "RSA");
    }

    public List<Certificate> getCertificate(){
        List<Certificate> list = Arrays.asList(tempList);
        return list;
    }

    private int getCertCount(){
        File certFile = new File(certificateFilePath);
        if (!certFile.isDirectory() && certFile.canRead()) {

            JSONParser jsonParser = new JSONParser();

            try {
                FileReader certFileReader = new FileReader(certFile);
                JSONObject certObj = (JSONObject) jsonParser.parse(certFileReader);
                JSONArray array = (JSONArray) certObj.get("list");
                return array.size();
            } catch ( Exception e) {
                loggerInstance.log(getClass(), "Config file can not be read!\n" + e.toString(), Logger.LogLevel.ERROR);
            }
        }
        return 0;
    }



    
}
