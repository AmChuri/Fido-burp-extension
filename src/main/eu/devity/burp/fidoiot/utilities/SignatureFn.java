package src.main.eu.devity.burp.fidoiot.utilities;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

import java.util.Objects;
import java.security.MessageDigest;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.security.InvalidKeyException;
import java.security.SignatureException;

public class SignatureFn {
    
    private static final Logger loggerInstance = Logger.getInstance();

    public SignatureFn(){

    }

        // for private signature
        public String computeSignature(String modText, String privateKeyContent, String keyinstanceType, String sigType) {
            loggerInstance.log(getClass(), "Compute Signature", Logger.LogLevel.INFO);
            MessageDigest md;
            
            try {
                KeyFactory kf = KeyFactory.getInstance(keyinstanceType);
                PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
                loggerInstance.log(getClass(), privateKeyContent, Logger.LogLevel.INFO);
    
                PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);
                Signature signature = Signature.getInstance(sigType);
                signature.initSign(privKey);
    
                signature.update(modText.getBytes());
                byte[] digitalSignature = signature.sign();
                String test = Base64.getEncoder().encodeToString(digitalSignature);
                loggerInstance.log(getClass(), test, Logger.LogLevel.INFO);
                return test;
    
            }
            catch (InvalidKeySpecException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e){
                loggerInstance.log(getClass(), e.toString(), Logger.LogLevel.ERROR);
                loggerInstance.log(getClass(), "Compute Signature this", Logger.LogLevel.ERROR);
            }
            return "";
        }
}
