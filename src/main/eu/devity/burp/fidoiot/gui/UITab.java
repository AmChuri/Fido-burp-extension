package src.main.eu.devity.burp.fidoiot.gui;

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
import java.io.PrintWriter;

import java.awt.Component;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.TableModel;

/**
 * Main UI Tab calling all the other classes
 */
public class UITab extends JTabbedPane implements ITab, IContextMenuFactory  {


    private static PrintWriter stdout;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JTabbedPane attackerTabGroup = new JTabbedPane();
    private int globalTabCounter = 0;

    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;

    private AttackTabPanel attackTabPanel;
    private CertificatePanel certificatePanel;

    private SignatureTab signatureTab;
    private helpPanel helpPanelTab;

    private javax.swing.JLabel tabhead;
    private IHttpRequestResponse currentlyDisplayedItem;



    public UITab(IBurpExtenderCallbacks callbacks) {
        this.helpers = callbacks.getHelpers();
        this.callbacks = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        initComponents();
    }


    /**
     * Initialize UI Components
     */
    private void initComponents() {

        stdout.println("Initialize FIDO IoT Protocol Analysis UI");
        signatureTab = new SignatureTab(callbacks);
        certificatePanel = new CertificatePanel();
        helpPanelTab = new helpPanel();

        this.addTab("Attacks", attackerTabGroup);
        this.addTab("Certificates", certificatePanel);
        this.addTab("Signature", signatureTab);
        this.addTab("Help", helpPanelTab);
        // Use Burp UI settings and add as extension tab
        callbacks.customizeUiComponent(this);
        callbacks.addSuiteTab(this);
    }

    /**
     * Get the UI component
     *
     * @return Get the UI component that should be registered at the Burp GUI.
     */
    @Override
    public Component getUiComponent() {
        return this;
    }

    /**
     * Create context menu
     * <p>
     * Create context menu for marked messages to create new {@link AttackerPanel} for this message
     */
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {
        IHttpRequestResponse[] messages = iContextMenuInvocation.getSelectedMessages();
        if (messages != null && messages.length == 1) {

            final IHttpRequestResponse message = messages[0];
            IHttpService httpService = message.getHttpService();

            java.util.List<JMenuItem> list = new ArrayList<>();
            JMenuItem menuItem = new JMenuItem("Send to FIDO");
            menuItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent evt) {
                    try {
                        IRequestInfo requestInfo = helpers.analyzeRequest(message);
                        int port = httpService.getPort();

                        // Create new attacker panel for this message
                        AttackTabPanel attackTabPanel = new AttackTabPanel(callbacks, message);
                        int newTabCounter = getNewGlobalTabCounter();
                        final String captionTitleValue = Integer.toString(newTabCounter);
                        attackerTabGroup.addTab(captionTitleValue, attackTabPanel);
                        attackerTabGroup.setSelectedIndex(attackerTabGroup.indexOfTab(captionTitleValue));



                        tabhead = new javax.swing.JLabel();
                        tabhead.setText("Attack");

                        // Tab caption
                        JPanel tabCaptionPanel = new JPanel(new GridBagLayout());
                        tabCaptionPanel.setOpaque(false);
                        JLabel captionTitle = new JLabel(captionTitleValue);
                        captionTitle.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 3));

                        // Define close button
                        final JButton closeButton = new JButton("x");
                        closeButton.setToolTipText("Click to close tab.");
                        closeButton.setOpaque(false);
                        closeButton.setContentAreaFilled(false);
                        closeButton.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
                        closeButton.setPreferredSize(new Dimension(18, 18));
                        closeButton.setMargin(new Insets(0, 0, 0, 0));
                        closeButton.setForeground(Color.gray);

                        // Close button mouse listener performing the tab
                        // removal on mouse click and defining hover effects
                        closeButton.addMouseListener(new MouseListener() {

                            @Override
                            public void mouseClicked(MouseEvent e) {
                                int index = attackerTabGroup.indexOfTab(captionTitleValue);

                                if (index >= 0) {
                                    attackerTabGroup.removeTabAt(index);
                                }
                            }

                            @Override
                            public void mousePressed(MouseEvent e) {
                            }

                            @Override
                            public void mouseReleased(MouseEvent e) {
                            }

                            @Override
                            public void mouseEntered(MouseEvent e) {
                                closeButton.setForeground(Color.black);
                            }

                            @Override
                            public void mouseExited(MouseEvent e) {
                                closeButton.setForeground(Color.gray);
                            }
                        });

                        GridBagConstraints gridBagConstraints = new GridBagConstraints();
                        gridBagConstraints.gridx = 0;
                        gridBagConstraints.gridy = 0;
                        gridBagConstraints.weightx = 1;
                        tabCaptionPanel.add(captionTitle, gridBagConstraints);

                        gridBagConstraints.gridx++;
                        gridBagConstraints.weightx = 0;
                        tabCaptionPanel.add(closeButton, gridBagConstraints);
                        attackerTabGroup.setTabComponentAt(attackerTabGroup.indexOfTab(captionTitleValue), tabCaptionPanel);

                    } catch (Exception e) {
                        stdout.println(e);
                    }
                }
            });
            list.add(menuItem);

            menuItem.setEnabled(true);




            return list;
        }

        return null;
    }

    @Override
    public String getTabCaption()
    {
        return "FIDO";
    }


    /**
     * Get the current tab index
     *
     * @return the tab index.
     */
    public int getGlobalTabCounter() {
        return globalTabCounter;
    }

    /**
     * Increase the tab index and get new value
     *
     * @return the increased tab index.
     */
    public int getNewGlobalTabCounter() {
        globalTabCounter++;
        return globalTabCounter;
    }

}
