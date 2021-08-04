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

    private IHttpRequestResponse requestResponse;
    private IRequestInfo requestInfo;

    private SignatureExcl sigExcl;

    private javax.swing.JLabel tabhead;




    private javax.swing.JComboBox<String> attackList;
    private javax.swing.JLabel attackListLabel;
    private javax.swing.JLabel typeLabel;
    private javax.swing.JLabel typeValue;
    private javax.swing.JTextArea inputValue;

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

        String country[]={"Signature Excl", "Key Confusion", "SSRF"};

        String request = new String(requestResponse.getRequest());
        String messageBody = request.substring(requestInfo.getBodyOffset());

        inputValue = new javax.swing.JTextArea(messageBody);
        inputValue. setRows(10);
        inputValue.setColumns(15);
        inputValue.setBounds(10,30, 200,200);

        JComboBox cb=new JComboBox(country);

        JButton button = new JButton("Attack");

        button.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                performAttack(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);

        layout.setHorizontalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING).addGroup(
                layout.createSequentialGroup()
                        .addComponent(cb)
//                        .addComponent(inputValue)
                        .addComponent(button)));
        layout.setVerticalGroup(
                layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(cb)
//                        .addComponent(inputValue)
                        .addComponent(button));
    }

    private void performAttack(java.awt.event.ActionEvent evt) {

        stdout.println(requestInfo.getUrl());

        sigExcl.signatureAttack();

    }


}