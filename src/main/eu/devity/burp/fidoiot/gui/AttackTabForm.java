package devity.burp.fidoiot.gui;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class AttackTabForm {
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

    public AttackTabForm() {
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
    }

    private void createUIComponents() {
        // TODO: place custom component creation code here
    }
}
