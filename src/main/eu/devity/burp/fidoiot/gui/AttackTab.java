package burp;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import static javax.swing.GroupLayout.Alignment.*;



public class AttackTab extends JPanel{

    private static PrintWriter stdout;
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private static final Logger loggerInstance = Logger.getInstance();

    private IHttpRequestResponse requestResponse;
    private IRequestInfo requestInfo;

    private SignatureExcl sigExcl;

    private javax.swing.JLabel tabhead;

    private javax.swing.JComboBox<String> attackList;
    private javax.swing.JLabel attackListLabel;
    private javax.swing.JLabel typeLabel, typeValue;
    private JComboBox cb;

    private javax.swing.JLabel proxyLabel, proxyURLLabel, proxyPortLabel, privaKeyLabel, autoInputLabel, autoInputValLabel, autoInputPortLabel;
    private JCheckBox proxycheckbx;
    private boolean proxySet;
    private javax.swing.JLabel hostHeaderLabel;

//    private javax.swing.JLabel typeValue;
    private javax.swing.JTextArea inputValue, customInputValue, privKeyField;
    private javax.swing.JTextField inputProxyURL, inputProxyPort, autoInputField, autoInputPort;

    private JScrollPane textScrollPane, customInputScrollPane, privKeyScrollPane;


    private SSRFAttack ssrfAttack;


    //need to implement
//    public enum AttackType {
//        Si,
//        INFO,
//        DEBUG
//    }

    public AttackTab(IBurpExtenderCallbacks callbacks, IHttpRequestResponse message){

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.requestResponse = message;
        this.requestInfo = helpers.analyzeRequest(message);
        this.stdout = new PrintWriter(callbacks.getStdout(), true);


        sigExcl = new SignatureExcl(callbacks, message);
        ssrfAttack = new SSRFAttack(callbacks, message);
        initComponents();

    }


    private void initComponents() {

        typeLabel = new javax.swing.JLabel();
        attackListLabel = new javax.swing.JLabel();
        privaKeyLabel = new javax.swing.JLabel();
        attackList = new javax.swing.JComboBox<>();


        typeLabel.setText("Type of Attack:");
        attackListLabel.setText("Temp placeholder:");

        String attackType[]={"Signature Excl", "Key Confusion", "SSRF"};

        String request = new String(requestResponse.getRequest());
        String messageBody = request.substring(requestInfo.getBodyOffset());

        inputValue = new javax.swing.JTextArea(request);
        customInputValue = new javax.swing.JTextArea(messageBody);

        // new field for adding private key
        String temp = new String("");
        privaKeyLabel.setText("Private Key");
        privKeyField = new javax.swing.JTextArea(temp);

        customInputValue.setRows(2);
        customInputValue.setColumns(2);
        inputValue.setRows(10);
        inputValue.setColumns(15);
        inputValue.setBounds(10,30, 200,200);


        textScrollPane= new JScrollPane(inputValue);
        textScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        textScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

        customInputScrollPane= new JScrollPane(customInputValue);
        customInputScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        customInputScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

        // automatic key input
        autoInputValLabel = new javax.swing.JLabel();
        autoInputLabel= new javax.swing.JLabel();
        autoInputPortLabel = new javax.swing.JLabel();
        autoInputLabel.setText("Input: ");
        autoInputValLabel.setText("Input Value:");
        autoInputPortLabel.setText("Input Port:");
        autoInputField = new JTextField();
        autoInputPort = new JTextField();

        privKeyScrollPane= new JScrollPane(privKeyField);
        privKeyScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        privKeyScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        

        cb = new JComboBox(attackType);

        JButton button = new JButton("Attack");
        JButton modify = new JButton("Modify Request");
        JButton autoAttack = new JButton("Auto Attack");
        JButton analyze = new JButton("Analyze");

        // SSRf WIP
        proxyLabel = new javax.swing.JLabel();
        proxyURLLabel = new javax.swing.JLabel();
        proxyPortLabel = new javax.swing.JLabel();
        proxyLabel.setText("Proxy: ");
        proxyURLLabel.setText("Proxy URL:");
        proxyPortLabel.setText("Proxy Port:");
        proxycheckbx = new JCheckBox();
        inputProxyURL = new JTextField();
        inputProxyPort = new JTextField();

        // Proxy checkbox listener
        proxycheckbx.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                proxySet = true;
            }
        });
        JButton hostheaderSSRFBtn = new JButton("Host Header Attack");
        JButton protocolsmugBtn = new JButton("Protocol Smuggling Attack");
        hostheaderSSRFBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                String modText=customInputValue.getText();
                if(proxySet){
                    ssrfAttack.hostheaderAttack(modText,proxySet,inputProxyURL.getText(),Integer.parseInt(inputProxyPort.getText()));
                } else {
                    ssrfAttack.hostheaderAttack(modText,proxySet,"0",0);
                }
            }
        });
        protocolsmugBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                String modText=customInputValue.getText();
                if(proxySet){
                    ssrfAttack.protcolSmugAttack(modText,proxySet,inputProxyURL.getText(),Integer.parseInt(inputProxyPort.getText()));
                } else {
                    ssrfAttack.protcolSmugAttack(modText,proxySet,"0",0);
                }

            }
        });


        JButton button1 = new JButton("test");

        button.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
//                performAttack(evt);
                if(proxySet){
                    performAttack(evt,messageBody,proxySet,inputProxyURL.getText(),Integer.parseInt(inputProxyPort.getText()));
                } else {
                    performAttack(evt,messageBody,proxySet,"0",0);
                }
            }
        });
        analyze.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                analyzeMessage(evt);
            }
        });

        modify.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
//                    modifyRequest(evt);
                if(proxySet){
                    modifyRequest(evt,proxySet,inputProxyURL.getText(),Integer.parseInt(inputProxyPort.getText()));
                } else {
                    modifyRequest(evt,proxySet,"0",0);
                }
            }
        });
        autoAttack.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                autoAttackSigExcl(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        layout.setHorizontalGroup(
                layout.createSequentialGroup().addGroup(
                        layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addComponent(cb,javax.swing.GroupLayout.PREFERRED_SIZE, 351,
                                javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(typeLabel)
                        .addComponent(privaKeyLabel)
                        .addComponent(privKeyScrollPane,javax.swing.GroupLayout.PREFERRED_SIZE, 350,
                                javax.swing.GroupLayout.PREFERRED_SIZE)
//                                .addComponent(attackListLabel)
                        )
//                .addComponent(inputValue,javax.swing.GroupLayout.PREFERRED_SIZE, 800,
//                        javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(textScrollPane,javax.swing.GroupLayout.PREFERRED_SIZE, 800,
                                javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
//                        .addComponent(customInputValue,javax.swing.GroupLayout.PREFERRED_SIZE, 750,
//                                javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(customInputScrollPane,javax.swing.GroupLayout.PREFERRED_SIZE, 750,
                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGroup(layout.createSequentialGroup()
                        .addComponent(button).addComponent(modify).addComponent(autoAttack))
                                .addGroup(layout.createSequentialGroup()
                                        .addComponent(analyze))
                                        // automatic  input value
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addGroup(layout.createSequentialGroup()
                                        .addComponent(autoInputLabel))
                                        .addGroup(layout.createSequentialGroup()
                                        .addComponent(autoInputValLabel).addComponent(autoInputField, 20, 30, 200))
                                        .addGroup(layout.createSequentialGroup()
                                        .addComponent(autoInputPortLabel).addComponent(autoInputPort, 20, 30, 60))
                                )
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addGroup(layout.createSequentialGroup()
                                        .addComponent(proxyLabel).addComponent(proxycheckbx))
                                        .addGroup(layout.createSequentialGroup()
                                        .addComponent(proxyURLLabel).addComponent(inputProxyURL, 20, 30, 200))
                                        .addGroup(layout.createSequentialGroup()
                                        .addComponent(proxyPortLabel).addComponent(inputProxyPort, 20, 30, 60))
                                )
                                .addGroup(layout.createSequentialGroup()
                                        .addComponent(hostheaderSSRFBtn)
                                ).addGroup(layout.createSequentialGroup()
                                        .addComponent(protocolsmugBtn)
                                )
            )
        );

        layout.setVerticalGroup(
                layout.createSequentialGroup().addGroup(
                        layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addGroup(layout.createSequentialGroup()
                                .addComponent(cb,javax.swing.GroupLayout.PREFERRED_SIZE, 25,
                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(typeLabel,javax.swing.GroupLayout.PREFERRED_SIZE, 100,
                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(privaKeyLabel,javax.swing.GroupLayout.PREFERRED_SIZE, 25,
                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(privKeyScrollPane,javax.swing.GroupLayout.PREFERRED_SIZE, 200,
                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                )
//                                .addComponent(attackListLabel,javax.swing.GroupLayout.PREFERRED_SIZE, 200,
//                                        javax.swing.GroupLayout.PREFERRED_SIZE)
//                                .addComponent(inputValue,javax.swing.GroupLayout.PREFERRED_SIZE, 400,
//                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(textScrollPane,javax.swing.GroupLayout.PREFERRED_SIZE, 400,
                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGroup(layout.createSequentialGroup().
//                                        addComponent(customInputValue,javax.swing.GroupLayout.PREFERRED_SIZE, 100,
//                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                 addComponent(customInputScrollPane,javax.swing.GroupLayout.PREFERRED_SIZE, 200,
        javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(button).addComponent(modify).addComponent(autoAttack))
                                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(analyze))
                                                // automatic input
                                                .addGroup(layout.createSequentialGroup()
                                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(autoInputLabel))
                                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(autoInputValLabel)
                                                        .addComponent(autoInputField, 20, 30, 30))
                                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(autoInputPortLabel).addComponent(autoInputPort, 20, 30, 30))
                                                )
                                                .addGroup(layout.createSequentialGroup()
                                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(proxyLabel).addComponent(proxycheckbx))
                                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(proxyURLLabel)
                                                        .addComponent(inputProxyURL, 20, 30, 30))
                                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(proxyPortLabel).addComponent(inputProxyPort, 20, 30, 30))
                                                )
                                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(hostheaderSSRFBtn)
                                                )
                                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(protocolsmugBtn)
                                                )
                                )
                )
        );
        loggerInstance.log(getClass(), "Added Message to UI TAB", Logger.LogLevel.INFO);

    }

    /**
     * Perform Attack on Button click
     * @param evt
     */

    private void performAttack(java.awt.event.ActionEvent evt, String messageBody, boolean proxyVal, String proxyDNS, int proxyPort) {
        loggerInstance.log(getClass(), "Performing Manuel Attack", Logger.LogLevel.INFO);
//        String modText=inputValue.getText();
        int data = cb.getSelectedIndex();
        String modText=customInputValue.getText();
        if(data == 0){
            byte[] updatedReq = sigExcl.generateRequest(modText,proxyVal, proxyDNS, proxyPort);
            sigExcl.sendAttackReq();
        } else{
            // wip ssrf attack
            String privKey = privKeyField.getText();
            String inputVal = autoInputField.getText();
            String inputPort = autoInputPort.getText();
            ssrfAttack.autoAttack(messageBody,privKey, inputVal, inputPort, proxyVal, proxyDNS, proxyPort);
            loggerInstance.log(getClass(), "test", Logger.LogLevel.INFO);
        }

    }

    private void modifyRequest(java.awt.event.ActionEvent evt, boolean proxyVal, String proxyDNS, int proxyPort) {
        loggerInstance.log(getClass(), "Request was modified", Logger.LogLevel.INFO);
        String modText=customInputValue.getText();
        byte[] updatedReq = sigExcl.generateRequest(modText,proxyVal, proxyDNS, proxyPort);
        String test = new String(updatedReq);
        inputValue.setText(test);
    }

    private void autoAttackSigExcl(java.awt.event.ActionEvent evt){
        int data = cb.getSelectedIndex();
        loggerInstance.log(getClass(), Integer.toString(data), Logger.LogLevel.INFO);
        if(data == 0){
            sigExcl.autoAttackSigExcl();
        } else{
            loggerInstance.log(getClass(), "test", Logger.LogLevel.INFO);
        }
    }

    // analyze the message for type of attack
    private void analyzeMessage(java.awt.event.ActionEvent evt){
        int data = cb.getSelectedIndex();
        loggerInstance.log(getClass(), "Analyzing the request", Logger.LogLevel.INFO);
        String modText=customInputValue.getText();
       if(data == 0){
            // check for sign excl
            loggerInstance.log(getClass(), "Analyzing Sign Excl", Logger.LogLevel.INFO);
        } else if(data == 1){
            // check for keyconf
            loggerInstance.log(getClass(), "Analyzing keyconf", Logger.LogLevel.INFO);
        } else{
            // check for SSRF
            loggerInstance.log(getClass(), "Analyzing SSRF", Logger.LogLevel.INFO);
        }
    }



}