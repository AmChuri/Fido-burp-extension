package src.main.eu.devity.burp.fidoiot.utilities;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

import java.util.Objects;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.security.MessageDigest;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.math.BigInteger;
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
            String finalSign = "";
            try {
                KeyFactory kf = KeyFactory.getInstance(keyinstanceType);
                PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
                loggerInstance.log(getClass(), privateKeyContent, Logger.LogLevel.INFO);
    
                PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);
                Signature signature = Signature.getInstance(sigType);
                signature.initSign(privKey);
    
                signature.update(modText.getBytes());
                byte[] digitalSignature = signature.sign();
                finalSign = Base64.getEncoder().encodeToString(digitalSignature);
                loggerInstance.log(getClass(), finalSign, Logger.LogLevel.INFO);
                return finalSign;
    
            }
            catch (InvalidKeySpecException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e){
                loggerInstance.log(getClass(), e.toString(), Logger.LogLevel.ERROR);
                return "Error "+e.toString();
            }
        }

        // base64 length
        public int encodedByteLength(byte[] base64Sign){
            String signature = Base64.getEncoder().encodeToString(base64Sign); // passed as sg value
            byte[] decoded = Base64.getDecoder().decode(signature);
            String temp = String.format("%040x", new BigInteger(1, decoded)); // to calculate length
            return temp.length();
        }

        public byte[] hmac256SHAgen(byte[] secretKey, byte[] message, String signAlgorithm){
            // signAlgorithm - HmacSHA256
            byte[] hmacSha256 = null;
            try {
              Mac mac = Mac.getInstance(signAlgorithm);
              SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, signAlgorithm);
              mac.init(secretKeySpec);
              hmacSha256 = mac.doFinal(message);
              return hmacSha256;
            } catch (Exception e) {
              throw new RuntimeException("Failed to calculate hmac-sha256", e);
              
            }
          }

          // key formatter
          public String keyNoHeadFootFormat(String pemKey){
            String pubKey;
            if(pemKey.contains("PUBLIC")){
              pubKey = pemKey.replaceAll("(-+BEGIN PUBLIC KEY-+\\r?\\n|-+END PUBLIC KEY-+\\r?\\n?)", "");
            } else {
              pubKey = pemKey.replaceAll("(-+BEGIN PRIVATE KEY-+\\r?\\n|-+END PRIVATE KEY-+\\r?\\n?)", "");
            }
            loggerInstance.log(getClass(), pubKey, Logger.LogLevel.INFO);
            return pubKey;
          }
          public String keyStringFormat(String pemKey){
            String pubKey;
            if(pemKey.contains("PUBLIC")){
                pubKey = pemKey.replaceAll("(-+BEGIN PUBLIC KEY-+\\r?\\n|-+END PUBLIC KEY-+\\r?\\n?)", "");
            } else {
                pubKey = pemKey.replaceAll("(-+BEGIN PRIVATE KEY-+\\r?\\n|-+END PRIVATE KEY-+\\r?\\n?)", "");
            }
            pubKey = pubKey.replace("\n", "").replace("\r", "");
            loggerInstance.log(getClass(), pubKey, Logger.LogLevel.INFO);
            return pubKey;
          }
}
