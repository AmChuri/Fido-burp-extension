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
//    private javax.swing.JLabel typeValue;
    private javax.swing.JTextArea inputValue, customInputValue;

    private JScrollPane textScrollPane, customInputScrollPane;

    public AttackTab(IBurpExtenderCallbacks callbacks, IHttpRequestResponse message){

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.requestResponse = message;
        this.requestInfo = helpers.analyzeRequest(message);
        this.stdout = new PrintWriter(callbacks.getStdout(), true);


        sigExcl = new SignatureExcl(callbacks, message);
        initComponents();

    }


    private void initComponents() {

        typeLabel = new javax.swing.JLabel();
        attackListLabel = new javax.swing.JLabel();
        attackList = new javax.swing.JComboBox<>();


        typeLabel.setText("Type of Attack:");
        attackListLabel.setText("Temp placeholder:");

        String attackType[]={"Signature Excl", "Key Confusion", "SSRF"};

        String request = new String(requestResponse.getRequest());
        String messageBody = request.substring(requestInfo.getBodyOffset());

        inputValue = new javax.swing.JTextArea(request);
        customInputValue = new javax.swing.JTextArea(messageBody);
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


        JComboBox cb=new JComboBox(attackType);

        JButton button = new JButton("Attack");
        JButton modify = new JButton("Modify Request");
        JButton autoAttack = new JButton("Auto Attack");

        button.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                performAttack(evt);
            }
        });

        modify.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                modifyReuest(evt);
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
            )
        );

        layout.setVerticalGroup(
                layout.createSequentialGroup().addGroup(
                        layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addGroup(layout.createSequentialGroup()
                                .addComponent(cb,javax.swing.GroupLayout.PREFERRED_SIZE, 25,
                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(typeLabel,javax.swing.GroupLayout.PREFERRED_SIZE, 200,
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
                                        .addComponent(button).addComponent(modify).addComponent(autoAttack)
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

    private void performAttack(java.awt.event.ActionEvent evt) {
        loggerInstance.log(getClass(), "Performing Manuel Attack", Logger.LogLevel.INFO);
        String modText=inputValue.getText();
        byte[] updatedReq = sigExcl.generateRequest(modText);
        sigExcl.sendAttackReq();

    }

    private void modifyReuest(java.awt.event.ActionEvent evt) {
        loggerInstance.log(getClass(), "Request was modified", Logger.LogLevel.INFO);
        String modText=customInputValue.getText();
        byte[] updatedReq = sigExcl.generateRequest(modText);
        String test = new String(updatedReq);
        inputValue.setText(test);
    }

    private void autoAttackSigExcl(java.awt.event.ActionEvent evt){
        sigExcl.autoAttackSigExcl();
    }




}