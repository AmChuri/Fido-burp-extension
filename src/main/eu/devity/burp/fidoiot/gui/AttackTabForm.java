package burp;

import burp.Logger;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;

public class AttackTabForm extends JPanel{

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private static final Logger loggerInstance = Logger.getInstance();
    private JPanel mainPanel;
    private JPanel attackPanel;
    private JComboBox attackType;
    private JComboBox subAttack;
    private JComboBox certSelect;
    private JPanel instructionPanel;
    private JTextPane instructionText;
    private JPanel reqPanel;
    private JScrollPane reqJPane;
    private JTextField request;
    private JPanel manualReqPanel;
    private JTextField manualReqText;
    private JScrollPane manualReqPane;
    private JPanel attackBtnPanel;
    private JPanel outputPanel;
    private JScrollPane outputScrollPane;
    private JTextArea outputText;
    private JPanel subBtnPanel;
    private JPanel proxyPanel;
    private JButton modifyBtn, analyzeBtn, attackBtn;
    private JLabel proxyLabel;
    private JTextField proxyHost;
    private JTextField proxyPort;
    private JPanel customInputPanel;
    private JTextField customInput;

    public AttackTabForm(IBurpExtenderCallbacks callbacks, IHttpRequestResponse message) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
//        this.requestResponse = message;
//        this.requestInfo = helpers.analyzeRequest(message);
this.setVisible(true);

        initComponents();
    }

    private void initComponents() {

        String attackTypeList[]={"Signature Excl", "Key Confusion", "SSRF"};

        this.attackType = new JComboBox(attackTypeList);
        this.subAttack = new JComboBox(attackTypeList);
        this.certSelect = new JComboBox(attackTypeList);
        this.attackBtn = new JButton("Attack");
        this.modifyBtn = new JButton("Modify");
        this.analyzeBtn = new JButton("Analyze");


        attackType.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

            }
        });
        subAttack.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

            }
        });
        certSelect.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

            }
        });
        attackBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

            }
        });
        modifyBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

            }
        });
        analyzeBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

            }
        });
    }

    private void createUIComponents() {
        // TODO: place custom component creation code here
    }
}
