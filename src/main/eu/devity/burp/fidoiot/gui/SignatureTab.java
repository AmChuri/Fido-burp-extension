package burp;

import burp.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.ResourceBundle;

import java.awt.Component;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.TableModel;
import javax.swing.*;
import java.awt.*;

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
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchProviderException;
import java.io.UnsupportedEncodingException;
import javax.crypto.*;
import java.lang.reflect.Array;
import javax.crypto.Cipher;

// used to compute signature from privkey
public class SignatureTab extends javax.swing.JPanel{

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private static final Logger loggerInstance = Logger.getInstance();

    private javax.swing.JTextArea bodyInput, keyInput, signatureOutput;
    private JScrollPane bodyScrollPane, keyScrollPane, outputScrollPane;
    private javax.swing.JLabel inputLabel, outputLabel, privKeyLabel;
    JButton button;
    private JComboBox dropdown;

    // List of Signatures supported
    // https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Signature
    private String signatureType[]={"SHA1withRSA", "SHA256withRSA", "SHA384withRSA", "SHA512withRSA",
            "NONEwithECDSA","SHA1withECDSA","SHA256withECDSA","SHA384withECDSA", "SHA512withECDSA"};

//    public enum signatureName {
//        0 ("SHA1withRSA"),
//        1 ("SHA256withRSA"),
//        2 ("SHA384withRSA"),
//        3 ("SHA512withRSA"),
//        4 ("NONEwithECDSA"),
//        5 ("SHA1withECDSA"),
//        6 ("SHA256withECDSA"),
//        7 ("SHA384withECDSA"),
//        8 ("SHA512withECDSA");
//
//        public final String label;
//
//        private signatureName(String label) {
//            this.label = label;
//        }
//    }

    public SignatureTab(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        initComponents();
    }

    /**
     * Initialize UI Components
     */
    private void initComponents() {
        loggerInstance.log(getClass(), "Signature Tab Init", Logger.LogLevel.INFO);



        dropdown=new JComboBox(signatureType);
        dropdown.setSelectedItem("SHA256withECDSA");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        bodyInput = new javax.swing.JTextArea();
        keyInput = new javax.swing.JTextArea();
        signatureOutput = new javax.swing.JTextArea();
        bodyInput.setRows(10);
        bodyInput.setColumns(15);
        bodyInput.setBounds(10,30, 200,200);
        bodyScrollPane= new JScrollPane(bodyInput);
        bodyScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        bodyScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

        keyInput.setRows(5);
        keyInput.setColumns(15);
        keyInput.setBounds(10,30, 200,200);
        keyScrollPane= new JScrollPane(keyInput);
        keyScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        keyScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

        signatureOutput.setRows(10);
        signatureOutput.setColumns(15);
        signatureOutput.setBounds(10,30, 200,200);
        outputScrollPane= new JScrollPane(signatureOutput);
        outputScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        outputScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

        button = new JButton("Compute");
        button.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                computeSignature(evt);
            }
        });

        layout.setHorizontalGroup(
                layout.createSequentialGroup().addComponent(bodyScrollPane,javax.swing.GroupLayout.PREFERRED_SIZE, 800,
                                javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addComponent(keyScrollPane,javax.swing.GroupLayout.PREFERRED_SIZE, 400,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(dropdown,javax.swing.GroupLayout.PREFERRED_SIZE, 351,
                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addGroup(layout.createSequentialGroup()
                                                .addComponent(button))
                        )
                        .addComponent(outputScrollPane,javax.swing.GroupLayout.PREFERRED_SIZE, 700,
                                javax.swing.GroupLayout.PREFERRED_SIZE)
        );
        layout.setVerticalGroup(
                layout.createSequentialGroup().addGroup(
                        layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(bodyScrollPane,javax.swing.GroupLayout.PREFERRED_SIZE, 400,
                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGroup(layout.createSequentialGroup().
        addComponent(keyScrollPane,javax.swing.GroupLayout.PREFERRED_SIZE, 200,
        javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(dropdown,javax.swing.GroupLayout.PREFERRED_SIZE, 25,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(button)
                                                )
                                )
                                .addComponent(outputScrollPane,javax.swing.GroupLayout.PREFERRED_SIZE, 400,
                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                )
        );

    }

    // for private signature
    private void computeSignature(java.awt.event.ActionEvent evt) {
        loggerInstance.log(getClass(), "Compute Signature", Logger.LogLevel.INFO);
        String modText=bodyInput.getText();
        MessageDigest md;
        String privateKeyContent = keyInput.getText();
        privateKeyContent = privateKeyContent.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");

        int selectedSignature = dropdown.getSelectedIndex();
        String temp = (String) Array.get(signatureType, selectedSignature);
        String keyinstanceType="EC";
        if(selectedSignature <=3 ){
            keyinstanceType="RSA";
        }
        try {
            KeyFactory kf = KeyFactory.getInstance(keyinstanceType);
            PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
//            X509EncodedKeySpec keySpecPKCS8 =
//                    new X509EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
            loggerInstance.log(getClass(), privateKeyContent, Logger.LogLevel.INFO);

            PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);
//            PublicKey privKey = kf.generatePublic(keySpecPKCS8);

//            loggerInstance.log(getClass(), test, Logger.LogLevel.INFO);
            Signature signature = Signature.getInstance(temp);
            signature.initSign(privKey);

//            verify for public key
//            signature.initVerify(privKey);
//            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding","SunJCE");
//            cipher.init(Cipher.ENCRYPT_MODE, privKey);
//            byte[] digitalSignature = cipher.doFinal(modText.getBytes("UTF8"));
//            String test = Base64.getEncoder().encodeToString(digitalSignature);
//            signature.update(modText.getBytes());
            byte[] digitalSignature = signature.sign();
//
            String test = Base64.getEncoder().encodeToString(digitalSignature);
            loggerInstance.log(getClass(), test, Logger.LogLevel.INFO);
            signatureOutput.setText(test);

        }
        catch (InvalidKeySpecException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e){
            loggerInstance.log(getClass(), e.toString(), Logger.LogLevel.ERROR);
            loggerInstance.log(getClass(), "Compute Signature this", Logger.LogLevel.ERROR);
        }
// SignatureException
        //NoSuchPaddingException
        //                | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException | UnsupportedEncodingException


//        sigExcl.sendAttackReq();

    }


}