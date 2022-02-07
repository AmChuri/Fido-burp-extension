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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;

import src.main.eu.devity.burp.fidoiot.utilities.custom.Certificate;

public class JsonParser {

    String userDir;
    Certificate[] tempList;
    private static final Logger loggerInstance = Logger.getInstance();

    public JsonParser() {
        userDir =  System.getProperty("user.home");

        tempList = new Certificate[5];
        populateCertificate();
    }


    public void readCertFile() {
        String userPath = this.userDir;
        try {
            loggerInstance.log(getClass(), userPath+"/Downloads/certlist1.json", Logger.LogLevel.INFO);
            // create object mapper instance
            ObjectMapper mapper = new ObjectMapper();
        
            loggerInstance.log(getClass(), "hey", Logger.LogLevel.INFO);
           // List<Certificate> certificates = Arrays.asList(mapper.readValue(Paths.get(userPath+"/Downloads/certlist.json").toFile(), Certificate[].class));
            Certificate obj = mapper.readValue(new File(userPath+"/Downloads/certlist.json"), Certificate.class);
            loggerInstance.log(getClass(), "hey", Logger.LogLevel.INFO);
            loggerInstance.log(getClass(), ""+obj.getName(), Logger.LogLevel.INFO);
           // for (final Certificate room : certificates) {
                // Here your room is available
            //    loggerInstance.log(getClass(), room.getName(), Logger.LogLevel.INFO);
           // }
            // print map entries
            //for (Map.Entry<?, ?> entry : map.entrySet()) {
            //    loggerInstance.log(getClass(), entry.getKey() + "=" + entry.getValue(), Logger.LogLevel.INFO);
            //}
        
        } catch (Exception ex) {
            loggerInstance.log(getClass(), ex.getMessage(), Logger.LogLevel.INFO);
            ex.printStackTrace();
        }
        
    }

    public void populateCertificate(){
        tempList[0] = new Certificate("/home/amey/thesis/keys/ocs/type22pubkey.pem", "Type 22 Public Key", "EC");
        tempList[1] = new Certificate("/home/amey/thesis/keys/ocs/type22privec256.pem", "Type 22 Private key", "EC");
        tempList[2] = new Certificate("/home/amey/thesis/keys/ocs/privec256.pem", "Custom EC 256", "EC");
        tempList[3] = new Certificate("/home/amey/thesis/keys/ocs/privec384.pem", "Custom EC 384", "EC");
        tempList[3] = new Certificate("/home/amey/thesis/keys/ocs/privrsa2048-owner.pem", "Custom RSA 2048", "RSA");
    }

    public List<Certificate> getCertificate(){
        List<Certificate> list = Arrays.asList(tempList);
        return list;
    }



    
}
