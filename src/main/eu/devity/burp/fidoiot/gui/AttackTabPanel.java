/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/GUIForms/JPanel.java to edit this template
 */
package burp;
import javax.swing.*;
import java.awt.*;
import javax.swing.BorderFactory;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;

/**
 *
 * @author amay
 */
public class AttackTabPanel extends javax.swing.JPanel {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private static final Logger loggerInstance = Logger.getInstance();

    private IHttpRequestResponse requestResponse;
    private IRequestInfo requestInfo;
    private String request;

    TitledBorder customInputTitle, reqTitle, outputTitle, instTitle;

    /**
     * Creates new form AttackTabPanel
     */
    public AttackTabPanel(IBurpExtenderCallbacks callbacks, IHttpRequestResponse message) {
        customInputTitle = BorderFactory.createTitledBorder("Custom Input");
        reqTitle = BorderFactory.createTitledBorder("Request");
        outputTitle = BorderFactory.createTitledBorder("Output");
        instTitle = BorderFactory.createTitledBorder("Instruction");
        
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.requestResponse = message;
        this.requestInfo = helpers.analyzeRequest(message);
        this.request = new String(requestResponse.getRequest());
        String messageBody = request.substring(requestInfo.getBodyOffset());
        initComponents();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        dropDownPanel = new javax.swing.JPanel();
        attackTypeList = new javax.swing.JComboBox<>();
        subAttackList = new javax.swing.JComboBox<>();
        certList = new javax.swing.JComboBox<>();
        attackTypeLabel = new javax.swing.JLabel();
        subAttackTypeLabel = new javax.swing.JLabel();
        certTypeLabel = new javax.swing.JLabel();
        requestPanel = new javax.swing.JPanel();
        requestPane = new javax.swing.JScrollPane();
        javax.swing.JTextPane requestText = new javax.swing.JTextPane();
        customInputPanel = new javax.swing.JPanel();
        customInputPane = new javax.swing.JScrollPane();
        customInputText = new javax.swing.JTextPane();
        customBtnPanel = new javax.swing.JPanel();
        inputLabel = new javax.swing.JLabel();
        customInput = new javax.swing.JTextField();
        proxyLabel = new javax.swing.JLabel();
        proxyCheck = new javax.swing.JCheckBox();
        proxyHostLabel = new javax.swing.JLabel();
        proxyHostText = new javax.swing.JTextField();
        proxyPortLabel = new javax.swing.JLabel();
        proxyPortText = new javax.swing.JTextField();
        modifyBtn = new javax.swing.JButton();
        analyzeBtn = new javax.swing.JButton();
        attackBtn = new javax.swing.JButton();
        outputPanel = new javax.swing.JPanel();
        outPutPane = new javax.swing.JScrollPane();
        OutputText = new javax.swing.JTextPane();
        instructionPanel = new javax.swing.JPanel();
        instPane = new javax.swing.JScrollPane();
        instructionText = new javax.swing.JTextPane();

        attackTypeList.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Signature Exclusion", "Key Confusion", "SSRF" }));
        attackTypeList.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                attackTypeListActionPerformed(evt);
            }
        });

        subAttackList.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Select Attack" }));

        certList.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Add Certificate" }));

        attackTypeLabel.setText("Attack");

        subAttackTypeLabel.setText("Sub Attack");

        certTypeLabel.setText("Certificate");

        javax.swing.GroupLayout dropDownPanelLayout = new javax.swing.GroupLayout(dropDownPanel);
        dropDownPanel.setLayout(dropDownPanelLayout);
        dropDownPanelLayout.setHorizontalGroup(
            dropDownPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(dropDownPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(dropDownPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(dropDownPanelLayout.createSequentialGroup()
                        .addComponent(attackTypeLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 62, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 20, Short.MAX_VALUE)
                        .addComponent(attackTypeList, javax.swing.GroupLayout.PREFERRED_SIZE, 220, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(dropDownPanelLayout.createSequentialGroup()
                        .addGroup(dropDownPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(subAttackTypeLabel)
                            .addComponent(certTypeLabel))
                        .addGap(20, 20, 20)
                        .addGroup(dropDownPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(certList, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(subAttackList, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
                .addGap(6, 6, 6))
        );
        dropDownPanelLayout.setVerticalGroup(
            dropDownPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(dropDownPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(dropDownPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(attackTypeList, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(attackTypeLabel))
                .addGap(20, 20, 20)
                .addGroup(dropDownPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(subAttackList, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(subAttackTypeLabel))
                .addGap(18, 20, Short.MAX_VALUE)
                .addGroup(dropDownPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(certList, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(certTypeLabel))
                .addGap(20, 20, 20))
        );

        requestText.setEditable(false);
        requestText.setBorder(reqTitle);
        requestText.setText(request);
        requestPane.setViewportView(requestText);

        javax.swing.GroupLayout requestPanelLayout = new javax.swing.GroupLayout(requestPanel);
        requestPanel.setLayout(requestPanelLayout);
        requestPanelLayout.setHorizontalGroup(
            requestPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(requestPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(requestPane, javax.swing.GroupLayout.DEFAULT_SIZE, 649, Short.MAX_VALUE)
                .addContainerGap())
        );
        requestPanelLayout.setVerticalGroup(
            requestPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(requestPanelLayout.createSequentialGroup()
                .addComponent(requestPane, javax.swing.GroupLayout.PREFERRED_SIZE, 388, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, Short.MAX_VALUE))
        );

        customInputText.setBorder(customInputTitle);
        customInputPane.setViewportView(customInputText);

        javax.swing.GroupLayout customInputPanelLayout = new javax.swing.GroupLayout(customInputPanel);
        customInputPanel.setLayout(customInputPanelLayout);
        customInputPanelLayout.setHorizontalGroup(
            customInputPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(customInputPanelLayout.createSequentialGroup()
                .addComponent(customInputPane, javax.swing.GroupLayout.PREFERRED_SIZE, 420, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, Short.MAX_VALUE))
        );
        customInputPanelLayout.setVerticalGroup(
            customInputPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(customInputPanelLayout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(customInputPane, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        inputLabel.setText("Input");
        inputLabel.setToolTipText("");

        proxyLabel.setText("Proxy");
        proxyLabel.setToolTipText("");

        proxyCheck.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                proxyCheckActionPerformed(evt);
            }
        });

        proxyHostLabel.setText("Proxy Host");
        proxyHostLabel.setToolTipText("");

        proxyPortLabel.setText("Proxy Host");
        proxyPortLabel.setToolTipText("");

        modifyBtn.setText("Modify");
        modifyBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                modifyBtnActionPerformed(evt);
            }
        });

        analyzeBtn.setText("Analyze");
        analyzeBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                analyzeBtnActionPerformed(evt);
            }
        });

        attackBtn.setText("Attack");
        attackBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                attackBtnActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout customBtnPanelLayout = new javax.swing.GroupLayout(customBtnPanel);
        customBtnPanel.setLayout(customBtnPanelLayout);
        customBtnPanelLayout.setHorizontalGroup(
            customBtnPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(customBtnPanelLayout.createSequentialGroup()
                .addGap(24, 24, 24)
                .addGroup(customBtnPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(customBtnPanelLayout.createSequentialGroup()
                        .addComponent(modifyBtn)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(analyzeBtn)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(attackBtn))
                    .addGroup(customBtnPanelLayout.createSequentialGroup()
                        .addGroup(customBtnPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(proxyPortLabel)
                            .addGroup(customBtnPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                .addComponent(proxyHostLabel)
                                .addComponent(inputLabel, javax.swing.GroupLayout.Alignment.LEADING)
                                .addComponent(proxyLabel, javax.swing.GroupLayout.Alignment.LEADING)))
                        .addGap(18, 18, 18)
                        .addGroup(customBtnPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(proxyCheck)
                            .addComponent(customInput, javax.swing.GroupLayout.PREFERRED_SIZE, 219, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(proxyHostText, javax.swing.GroupLayout.PREFERRED_SIZE, 219, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(proxyPortText, javax.swing.GroupLayout.PREFERRED_SIZE, 219, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        customBtnPanelLayout.setVerticalGroup(
            customBtnPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(customBtnPanelLayout.createSequentialGroup()
                .addGap(28, 28, 28)
                .addGroup(customBtnPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(inputLabel)
                    .addComponent(customInput, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(customBtnPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(proxyLabel)
                    .addComponent(proxyCheck))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(customBtnPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(proxyHostLabel)
                    .addComponent(proxyHostText, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(customBtnPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(proxyPortLabel)
                    .addComponent(proxyPortText, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(customBtnPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(modifyBtn)
                    .addComponent(analyzeBtn)
                    .addComponent(attackBtn))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        OutputText.setEditable(false);
        OutputText.setBorder(outputTitle);
        outPutPane.setViewportView(OutputText);

        javax.swing.GroupLayout outputPanelLayout = new javax.swing.GroupLayout(outputPanel);
        outputPanel.setLayout(outputPanelLayout);
        outputPanelLayout.setHorizontalGroup(
            outputPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(outputPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(outPutPane, javax.swing.GroupLayout.PREFERRED_SIZE, 1418, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        outputPanelLayout.setVerticalGroup(
            outputPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, outputPanelLayout.createSequentialGroup()
                .addGap(0, 0, Short.MAX_VALUE)
                .addComponent(outPutPane, javax.swing.GroupLayout.PREFERRED_SIZE, 352, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        instructionText.setEditable(false);
        instructionText.setBorder(instTitle);
        instPane.setViewportView(instructionText);

        javax.swing.GroupLayout instructionPanelLayout = new javax.swing.GroupLayout(instructionPanel);
        instructionPanel.setLayout(instructionPanelLayout);
        instructionPanelLayout.setHorizontalGroup(
            instructionPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(instructionPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(instPane, javax.swing.GroupLayout.PREFERRED_SIZE, 320, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        instructionPanelLayout.setVerticalGroup(
            instructionPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, instructionPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(instPane)
                .addContainerGap())
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(outputPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(instructionPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(12, 12, 12)
                                .addComponent(dropDownPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(requestPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(customInputPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(0, 0, Short.MAX_VALUE))
                            .addComponent(customBtnPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(customInputPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(customBtnPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(requestPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(dropDownPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(instructionPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(outputPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
    }// </editor-fold>//GEN-END:initComponents

    private void attackTypeListActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_attackTypeListActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_attackTypeListActionPerformed

    private void proxyCheckActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_proxyCheckActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_proxyCheckActionPerformed

    private void modifyBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_modifyBtnActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_modifyBtnActionPerformed

    private void analyzeBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_analyzeBtnActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_analyzeBtnActionPerformed

    private void attackBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_attackBtnActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_attackBtnActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextPane OutputText;
    private javax.swing.JButton analyzeBtn;
    private javax.swing.JButton attackBtn;
    private javax.swing.JLabel attackTypeLabel;
    private javax.swing.JComboBox<String> attackTypeList;
    private javax.swing.JComboBox<String> certList;
    private javax.swing.JLabel certTypeLabel;
    private javax.swing.JPanel customBtnPanel;
    private javax.swing.JTextField customInput;
    private javax.swing.JScrollPane customInputPane;
    private javax.swing.JPanel customInputPanel;
    private javax.swing.JTextPane customInputText;
    private javax.swing.JPanel dropDownPanel;
    private javax.swing.JLabel inputLabel;
    private javax.swing.JScrollPane instPane;
    private javax.swing.JPanel instructionPanel;
    private javax.swing.JTextPane instructionText;
    private javax.swing.JButton modifyBtn;
    private javax.swing.JScrollPane outPutPane;
    private javax.swing.JPanel outputPanel;
    private javax.swing.JCheckBox proxyCheck;
    private javax.swing.JLabel proxyHostLabel;
    private javax.swing.JTextField proxyHostText;
    private javax.swing.JLabel proxyLabel;
    private javax.swing.JLabel proxyPortLabel;
    private javax.swing.JTextField proxyPortText;
    private javax.swing.JScrollPane requestPane;
    private javax.swing.JPanel requestPanel;
    private javax.swing.JComboBox<String> subAttackList;
    private javax.swing.JLabel subAttackTypeLabel;
    // End of variables declaration//GEN-END:variables
}
