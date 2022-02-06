package src.main.eu.devity.burp.fidoiot.utilities;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;

import src.main.eu.devity.burp.fidoiot.utilities.custom.Certificate;

public class JsonParser {

    String userDir;
    private static final Logger loggerInstance = Logger.getInstance();

    public JsonParser() {
        userDir =  System.getProperty("user.home");
    }


    public void readCertFile() {
        String userPath = this.userDir;
        loggerInstance.log(getClass(), "hey", Logger.LogLevel.INFO);
        loggerInstance.log(getClass(), userPath, Logger.LogLevel.INFO);
        try {
            loggerInstance.log(getClass(), userPath+"/Downloads/certlist.json", Logger.LogLevel.INFO);
            // create object mapper instance
            ObjectMapper mapper = new ObjectMapper();
        

            List<Certificate> certificates = Arrays.asList(mapper.readValue(Paths.get(userPath+"/Downloads/certlist.json").toFile(), Certificate[].class));
            
            certificates.forEach(System.out::println);
            // print map entries
            //for (Map.Entry<?, ?> entry : map.entrySet()) {
            //    loggerInstance.log(getClass(), entry.getKey() + "=" + entry.getValue(), Logger.LogLevel.INFO);
            //}
        
        } catch (Exception ex) {
            loggerInstance.log(getClass(), ex.getMessage(), Logger.LogLevel.INFO);
            ex.printStackTrace();
        }
        
    }



    
}
