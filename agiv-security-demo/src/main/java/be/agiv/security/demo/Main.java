/*
 * AGIV Java Security Project.
 * Copyright (C) 2011-2012 AGIV.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */

package be.agiv.security.demo;

import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Proxy;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;

import javax.swing.Box;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.soap.AddressingFeature;
import javax.xml.ws.spi.Provider;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.tempuri.IService;
import org.tempuri.Service;

import be.agiv.ArrayOfClaimInfo;
import be.agiv.ClaimInfo;
import be.agiv.security.AGIVSecurity;
import be.agiv.security.STSListener;
import be.agiv.security.SecurityToken;
import be.agiv.security.client.IPSTSClient;
import be.agiv.security.client.RSTSClient;
import be.agiv.security.client.SecureConversationClient;

/**
 * Demonstrator Swing application for the AGIV Security framework.
 * <p/>
 * This demo should not require additional dependencies in order to keep the SDK
 * lib/ directory as clean as possible.
 * 
 * @author Frank Cornelis
 * 
 */
public class Main extends JFrame implements ActionListener, STSListener {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory.getLog(Main.class);

	private JMenuItem exitMenuItem;

	private JMenuItem ipStsIssueMenuItem;

	private JMenuItem ipStsViewMenuItem;

	private SecurityToken ipStsSecurityToken;

	private JMenuItem rStsIssueMenuItem;

	private JMenuItem rStsViewMenuItem;

	private SecurityToken rStsSecurityToken;

	private JMenuItem secConvIssueMenuItem;

	private JMenuItem secConvViewMenuItem;

	private JMenuItem secConvCancelMenuItem;

	private SecurityToken secConvSecurityToken;

	private JMenuItem claimsAwareServiceMenuItem;

	private JMenuItem aboutMenuItem;

	private JMenuItem preferencesMenuItem;

	private String proxyHost;

	private int proxyPort;

	private Proxy.Type proxyType;

	private boolean proxyEnable;

	private AGIVSecurity agivSecurity;

	private final StatusBar statusBar;

	public Main() {
		super("AGIV Java Security Demo");

		addMenuBar();

		this.statusBar = new StatusBar();
		this.statusBar.setStatus("Welcome to the AGIV Security Demo.");
		Container contentPane = this.getContentPane();
		contentPane.add(this.statusBar, BorderLayout.SOUTH);

		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setSize(450, 300);
		setVisible(true);
	}

	private void addMenuBar() {
		JMenuBar menuBar = new JMenuBar();
		setJMenuBar(menuBar);

		JMenu fileMenu = new JMenu("File");
		menuBar.add(fileMenu);
		this.preferencesMenuItem = new JMenuItem("Preferences");
		fileMenu.add(this.preferencesMenuItem);
		this.preferencesMenuItem.addActionListener(this);
		fileMenu.addSeparator();
		this.exitMenuItem = new JMenuItem("Exit");
		fileMenu.add(this.exitMenuItem);
		this.exitMenuItem.addActionListener(this);

		JMenu ipStsMenu = new JMenu("IP-STS");
		menuBar.add(ipStsMenu);
		this.ipStsIssueMenuItem = new JMenuItem("Issue token");
		ipStsMenu.add(this.ipStsIssueMenuItem);
		this.ipStsIssueMenuItem.addActionListener(this);
		this.ipStsViewMenuItem = new JMenuItem("View token");
		ipStsMenu.add(this.ipStsViewMenuItem);
		this.ipStsViewMenuItem.addActionListener(this);
		this.ipStsViewMenuItem.setEnabled(false);

		JMenu rStsMenu = new JMenu("R-STS");
		menuBar.add(rStsMenu);
		this.rStsIssueMenuItem = new JMenuItem("Issue token");
		rStsMenu.add(this.rStsIssueMenuItem);
		this.rStsIssueMenuItem.addActionListener(this);
		this.rStsIssueMenuItem.setEnabled(false);
		this.rStsViewMenuItem = new JMenuItem("View token");
		rStsMenu.add(this.rStsViewMenuItem);
		this.rStsViewMenuItem.addActionListener(this);
		this.rStsViewMenuItem.setEnabled(false);

		JMenu secConvMenu = new JMenu("Secure Conversation");
		menuBar.add(secConvMenu);
		this.secConvIssueMenuItem = new JMenuItem("Issue token");
		secConvMenu.add(this.secConvIssueMenuItem);
		this.secConvIssueMenuItem.addActionListener(this);
		this.secConvIssueMenuItem.setEnabled(false);
		this.secConvViewMenuItem = new JMenuItem("View token");
		secConvMenu.add(this.secConvViewMenuItem);
		this.secConvViewMenuItem.addActionListener(this);
		this.secConvViewMenuItem.setEnabled(false);
		this.secConvCancelMenuItem = new JMenuItem("Cancel token");
		secConvMenu.add(this.secConvCancelMenuItem);
		this.secConvCancelMenuItem.addActionListener(this);
		this.secConvCancelMenuItem.setEnabled(false);

		JMenu servicesMenu = new JMenu("Services");
		menuBar.add(servicesMenu);
		this.claimsAwareServiceMenuItem = new JMenuItem("Claims aware service");
		servicesMenu.add(this.claimsAwareServiceMenuItem);
		this.claimsAwareServiceMenuItem.addActionListener(this);

		menuBar.add(Box.createHorizontalGlue());
		JMenu helpMenu = new JMenu("Help");
		menuBar.add(helpMenu);
		this.aboutMenuItem = new JMenuItem("About");
		helpMenu.add(this.aboutMenuItem);
		this.aboutMenuItem.addActionListener(this);
	}

	public void actionPerformed(ActionEvent e) {
		if (e.getSource() == this.exitMenuItem) {
			dispose();
			System.exit(0);
		}
		if (e.getSource() == this.ipStsIssueMenuItem) {
			ipStsIssueToken();
		} else if (e.getSource() == this.claimsAwareServiceMenuItem) {
			invokeClaimsAwareService();
		} else if (e.getSource() == this.aboutMenuItem) {
			showAbout();
		} else if (e.getSource() == this.preferencesMenuItem) {
			showPreferences();
		} else if (e.getSource() == this.ipStsViewMenuItem) {
			ipStsViewToken();
		} else if (e.getSource() == this.rStsIssueMenuItem) {
			rStsIssueToken();
		} else if (e.getSource() == this.rStsViewMenuItem) {
			rStsViewToken();
		} else if (e.getSource() == this.secConvIssueMenuItem) {
			secConvIssueToken();
		} else if (e.getSource() == this.secConvViewMenuItem) {
			secConvViewToken();
		} else if (e.getSource() == this.secConvCancelMenuItem) {
			secConvCancelToken();
		}
	}

	private void secConvCancelToken() {
		GridBagLayout gridBagLayout = new GridBagLayout();
		GridBagConstraints gridBagConstraints = new GridBagConstraints();
		JPanel contentPanel = new JPanel(gridBagLayout);

		JLabel urlLabel = new JLabel("URL:");
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 0;
		gridBagConstraints.anchor = GridBagConstraints.WEST;
		gridBagConstraints.ipadx = 5;
		gridBagLayout.setConstraints(urlLabel, gridBagConstraints);
		contentPanel.add(urlLabel);

		JTextField urlTextField = new JTextField(
				ClaimsAwareServiceFactory.SERVICE_SC_LOCATION, 60);
		gridBagConstraints.gridx++;
		gridBagLayout.setConstraints(urlTextField, gridBagConstraints);
		contentPanel.add(urlTextField);

		int result = JOptionPane.showConfirmDialog(this, contentPanel,
				"Secure Conversation Cancel Token",
				JOptionPane.OK_CANCEL_OPTION);
		if (result == JOptionPane.CANCEL_OPTION) {
			return;
		}

		String location = urlTextField.getText();

		SecureConversationClient secConvClient = new SecureConversationClient(
				location);
		try {
			secConvClient
					.cancelSecureConversationToken(this.secConvSecurityToken);
			this.secConvViewMenuItem.setEnabled(false);
			this.secConvCancelMenuItem.setEnabled(false);
			this.secConvSecurityToken = null;
			JOptionPane.showMessageDialog(this,
					"Secure conversation token cancelled.",
					"Secure Conversation", JOptionPane.INFORMATION_MESSAGE);
		} catch (Exception e) {
			showException(e);
		}
	}

	private void secConvViewToken() {
		showToken(this.secConvSecurityToken, "Secure Conversation");
	}

	private void secConvIssueToken() {
		GridBagLayout gridBagLayout = new GridBagLayout();
		GridBagConstraints gridBagConstraints = new GridBagConstraints();
		JPanel contentPanel = new JPanel(gridBagLayout);

		JLabel urlLabel = new JLabel("URL:");
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 0;
		gridBagConstraints.anchor = GridBagConstraints.WEST;
		gridBagConstraints.ipadx = 5;
		gridBagLayout.setConstraints(urlLabel, gridBagConstraints);
		contentPanel.add(urlLabel);

		JTextField urlTextField = new JTextField(
				ClaimsAwareServiceFactory.SERVICE_SC_LOCATION, 60);
		gridBagConstraints.gridx++;
		gridBagLayout.setConstraints(urlTextField, gridBagConstraints);
		contentPanel.add(urlTextField);

		JLabel warningLabel = new JLabel(
				"This operation can fail if the web service does not support WS-SecurityConversation.");
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy++;
		gridBagConstraints.gridwidth = GridBagConstraints.REMAINDER;
		gridBagLayout.setConstraints(warningLabel, gridBagConstraints);
		contentPanel.add(warningLabel);

		int result = JOptionPane
				.showConfirmDialog(this, contentPanel,
						"Secure Conversation Issue Token",
						JOptionPane.OK_CANCEL_OPTION);
		if (result == JOptionPane.CANCEL_OPTION) {
			return;
		}

		String location = urlTextField.getText();

		SecureConversationClient secConvClient = new SecureConversationClient(
				location);
		try {
			this.secConvSecurityToken = secConvClient
					.getSecureConversationToken(this.rStsSecurityToken);
			this.secConvViewMenuItem.setEnabled(true);
			this.secConvCancelMenuItem.setEnabled(true);
			secConvViewToken();
		} catch (Exception e) {
			showException(e);
		}
	}

	private void rStsIssueToken() {
		GridBagLayout gridBagLayout = new GridBagLayout();
		GridBagConstraints gridBagConstraints = new GridBagConstraints();
		JPanel contentPanel = new JPanel(gridBagLayout);

		JLabel urlLabel = new JLabel("URL:");
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 0;
		gridBagConstraints.anchor = GridBagConstraints.WEST;
		gridBagConstraints.ipadx = 5;
		gridBagLayout.setConstraints(urlLabel, gridBagConstraints);
		contentPanel.add(urlLabel);

		JTextField urlTextField = new JTextField(
				"https://auth.beta.agiv.be/sts/Services/SalvadorSecurityTokenServiceConfiguration.svc/IWSTrust13",
				60);
		gridBagConstraints.gridx++;
		gridBagLayout.setConstraints(urlTextField, gridBagConstraints);
		contentPanel.add(urlTextField);

		JLabel appliesToLabel = new JLabel("Applies to:");
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy++;
		gridBagLayout.setConstraints(appliesToLabel, gridBagConstraints);
		contentPanel.add(appliesToLabel);

		JTextField appliesToTextField = new JTextField(
				ClaimsAwareServiceFactory.SERVICE_REALM, 60);
		gridBagConstraints.gridx++;
		gridBagLayout.setConstraints(appliesToTextField, gridBagConstraints);
		contentPanel.add(appliesToTextField);

		int result = JOptionPane.showConfirmDialog(this, contentPanel,
				"R-STS Issue Token", JOptionPane.OK_CANCEL_OPTION);
		if (result == JOptionPane.CANCEL_OPTION) {
			return;
		}

		String location = urlTextField.getText();
		String appliesTo = appliesToTextField.getText();

		RSTSClient rStsClient = new RSTSClient(location);
		try {
			this.rStsSecurityToken = rStsClient.getSecurityToken(
					this.ipStsSecurityToken, appliesTo);
			this.rStsViewMenuItem.setEnabled(true);
			this.secConvIssueMenuItem.setEnabled(true);
			rStsViewToken();
		} catch (Exception e) {
			showException(e);
		}
	}

	private void ipStsViewToken() {
		showToken(this.ipStsSecurityToken, "IP-STS");
	}

	private void rStsViewToken() {
		showToken(this.rStsSecurityToken, "R-STS");
	}

	private void showToken(SecurityToken securityToken, String serviceName) {
		if (null == securityToken) {
			return;
		}
		StringBuffer stringBuffer = new StringBuffer();
		stringBuffer.append("Created: " + securityToken.getCreated());
		stringBuffer.append("\n");
		stringBuffer.append("Expires: " + securityToken.getExpires());
		stringBuffer.append("\n");
		stringBuffer.append("Key size: " + securityToken.getKey().length * 8
				+ " bits");
		stringBuffer.append("\n");
		stringBuffer.append("Unattached reference: "
				+ securityToken.getUnattachedReference());
		stringBuffer.append("\n");
		stringBuffer.append("Attached reference: "
				+ securityToken.getAttachedReference());
		JOptionPane.showMessageDialog(this, stringBuffer.toString(),
				serviceName + " Token", JOptionPane.INFORMATION_MESSAGE);
	}

	private void showPreferences() {
		JTabbedPane tabbedPane = new JTabbedPane();

		GridBagLayout proxyGridBagLayout = new GridBagLayout();
		GridBagConstraints proxyGridBagConstraints = new GridBagConstraints();
		JPanel proxyPanel = new JPanel(proxyGridBagLayout) {

			private static final long serialVersionUID = 1L;

			@Override
			public Insets getInsets() {
				return new Insets(10, 10, 10, 10);
			}
		};
		tabbedPane.addTab("Proxy", proxyPanel);

		JCheckBox proxyEnableCheckBox = new JCheckBox("Enable proxy",
				this.proxyEnable);
		proxyGridBagConstraints.gridx = 0;
		proxyGridBagConstraints.gridy = 0;
		proxyGridBagConstraints.anchor = GridBagConstraints.WEST;
		proxyGridBagConstraints.ipadx = 5;
		proxyGridBagConstraints.gridwidth = GridBagConstraints.REMAINDER;
		proxyGridBagLayout.setConstraints(proxyEnableCheckBox,
				proxyGridBagConstraints);
		proxyPanel.add(proxyEnableCheckBox);
		proxyGridBagConstraints.gridwidth = 1;

		JLabel proxyHostLabel = new JLabel("Host:");
		proxyGridBagConstraints.gridx = 0;
		proxyGridBagConstraints.gridy++;
		proxyGridBagLayout.setConstraints(proxyHostLabel,
				proxyGridBagConstraints);
		proxyPanel.add(proxyHostLabel);

		JTextField proxyHostTextField = new JTextField(this.proxyHost, 20);
		proxyGridBagConstraints.gridx++;
		proxyGridBagLayout.setConstraints(proxyHostTextField,
				proxyGridBagConstraints);
		proxyPanel.add(proxyHostTextField);

		JLabel proxyPortLabel = new JLabel("Port:");
		proxyGridBagConstraints.gridx = 0;
		proxyGridBagConstraints.gridy++;
		proxyGridBagLayout.setConstraints(proxyPortLabel,
				proxyGridBagConstraints);
		proxyPanel.add(proxyPortLabel);

		JTextField proxyPortTextField = new JTextField(
				Integer.toString(this.proxyPort), 8);
		proxyGridBagConstraints.gridx++;
		proxyGridBagLayout.setConstraints(proxyPortTextField,
				proxyGridBagConstraints);
		proxyPanel.add(proxyPortTextField);

		JLabel proxyTypeLabel = new JLabel("Type:");
		proxyGridBagConstraints.gridx = 0;
		proxyGridBagConstraints.gridy++;
		proxyGridBagLayout.setConstraints(proxyTypeLabel,
				proxyGridBagConstraints);
		proxyPanel.add(proxyTypeLabel);

		JComboBox proxyTypeComboBox = new JComboBox(new Object[] {
				Proxy.Type.HTTP, Proxy.Type.SOCKS });
		proxyTypeComboBox.setSelectedItem(this.proxyType);
		proxyGridBagConstraints.gridx++;
		proxyGridBagLayout.setConstraints(proxyTypeComboBox,
				proxyGridBagConstraints);
		proxyPanel.add(proxyTypeComboBox);

		int dialogResult = JOptionPane.showConfirmDialog(this, tabbedPane,
				"Preferences", JOptionPane.OK_CANCEL_OPTION);
		if (dialogResult == JOptionPane.CANCEL_OPTION) {
			return;
		}

		this.statusBar.setStatus("Applying new preferences...");
		this.proxyHost = proxyHostTextField.getText();
		this.proxyPort = Integer.parseInt(proxyPortTextField.getText());
		this.proxyType = (Proxy.Type) proxyTypeComboBox.getSelectedItem();
		this.proxyEnable = proxyEnableCheckBox.isSelected();
	}

	private void showAbout() {
		this.statusBar.setStatus("Written by Frank Cornelis");
		Provider jaxWsProvider = Provider.provider();
		JOptionPane.showMessageDialog(
				this,
				"AGIV Java Security Demo " + getVersion() + "\n"
						+ "Copyright (C) 2011-2013 AGIV.\n"
						+ "Licensed under GNU LGPL 3.0.\n\n" + "Java version: "
						+ System.getProperty("java.version") + "\n"
						+ "System: " + System.getProperty("os.name") + " "
						+ System.getProperty("os.version") + " "
						+ System.getProperty("os.arch") + "\n\n"
						+ "JAX-WS provider: "
						+ jaxWsProvider.getClass().getName(), "About",
				JOptionPane.INFORMATION_MESSAGE);
	}

	private void invokeClaimsAwareService() {
		GridBagLayout gridBagLayout = new GridBagLayout();
		GridBagConstraints gridBagConstraints = new GridBagConstraints();
		JPanel contentPanel = new JPanel(gridBagLayout);

		final JLabel ipStsLabel = new JLabel("IP-STS:");
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 0;
		gridBagConstraints.anchor = GridBagConstraints.WEST;
		gridBagConstraints.ipadx = 5;
		gridBagLayout.setConstraints(ipStsLabel, gridBagConstraints);
		contentPanel.add(ipStsLabel);

		final JTextField ipStsTextField = new JTextField(
				"https://auth.beta.agiv.be/ipsts/Services/DaliSecurityTokenServiceConfiguration.svc/IWSTrust13",
				60);
		gridBagConstraints.gridx++;
		gridBagLayout.setConstraints(ipStsTextField, gridBagConstraints);
		contentPanel.add(ipStsTextField);

		JLabel realmLabel = new JLabel("Realm:");
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy++;
		gridBagLayout.setConstraints(realmLabel, gridBagConstraints);
		contentPanel.add(realmLabel);

		JTextField realmTextField = new JTextField(AGIVSecurity.BETA_REALM, 30);
		gridBagConstraints.gridx++;
		gridBagLayout.setConstraints(realmTextField, gridBagConstraints);
		contentPanel.add(realmTextField);

		final CredentialPanel credentialPanel = new CredentialPanel();
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy++;
		gridBagConstraints.gridwidth = GridBagConstraints.REMAINDER;
		gridBagLayout.setConstraints(credentialPanel, gridBagConstraints);
		contentPanel.add(credentialPanel);

		final JLabel rStsLabel = new JLabel("R-STS:");
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy++;
		gridBagConstraints.gridwidth = 1;
		gridBagLayout.setConstraints(rStsLabel, gridBagConstraints);
		contentPanel.add(rStsLabel);

		final JTextField rStsTextField = new JTextField(
				"https://auth.beta.agiv.be/sts/Services/SalvadorSecurityTokenServiceConfiguration.svc/IWSTrust13",
				60);
		gridBagConstraints.gridx++;
		gridBagLayout.setConstraints(rStsTextField, gridBagConstraints);
		contentPanel.add(rStsTextField);

		JLabel serviceRealmLabel = new JLabel("Service realm:");
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy++;
		gridBagLayout.setConstraints(serviceRealmLabel, gridBagConstraints);
		contentPanel.add(serviceRealmLabel);

		JTextField serviceRealmTextField = new JTextField(
				ClaimsAwareServiceFactory.SERVICE_REALM, 60);
		gridBagConstraints.gridx++;
		gridBagLayout.setConstraints(serviceRealmTextField, gridBagConstraints);
		contentPanel.add(serviceRealmTextField);

		JLabel urlLabel = new JLabel("Service URL:");
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy++;
		gridBagLayout.setConstraints(urlLabel, gridBagConstraints);
		contentPanel.add(urlLabel);

		JTextField urlTextField = new JTextField(
				ClaimsAwareServiceFactory.SERVICE_LOCATION, 60);
		gridBagConstraints.gridx++;
		gridBagLayout.setConstraints(urlTextField, gridBagConstraints);
		contentPanel.add(urlTextField);

		final JCheckBox noWsPolicyCheckBox = new JCheckBox(
				"WSDL without WS-Policy");
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy++;
		gridBagConstraints.gridwidth = GridBagConstraints.REMAINDER;
		gridBagLayout.setConstraints(noWsPolicyCheckBox, gridBagConstraints);
		contentPanel.add(noWsPolicyCheckBox);

		final JCheckBox useWsSecureConversationCheckBox = new JCheckBox(
				"Use WS-SecureConversation");
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy++;
		gridBagConstraints.gridwidth = GridBagConstraints.REMAINDER;
		gridBagLayout.setConstraints(useWsSecureConversationCheckBox,
				gridBagConstraints);
		contentPanel.add(useWsSecureConversationCheckBox);

		final JCheckBox usePreviousSecurityCheckBox = new JCheckBox(
				"Use previous AGIV Security");
		final JCheckBox cancelPreviousSecureConversationToken = new JCheckBox(
				"Cancel previous conversation token");
		usePreviousSecurityCheckBox.setEnabled(null != this.agivSecurity);
		cancelPreviousSecureConversationToken.setEnabled(false);
		usePreviousSecurityCheckBox.addActionListener(new ActionListener() {

			public void actionPerformed(ActionEvent e) {
				LOG.debug("use previous security: "
						+ usePreviousSecurityCheckBox.isSelected());
				boolean newSecurity = !usePreviousSecurityCheckBox.isSelected();
				ipStsLabel.setEnabled(newSecurity);
				ipStsTextField.setEditable(newSecurity);
				credentialPanel.setEnabled(newSecurity);
				rStsLabel.setEnabled(newSecurity);
				rStsTextField.setEnabled(newSecurity);
				cancelPreviousSecureConversationToken.setEnabled(!newSecurity);
			}
		});
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy++;
		gridBagConstraints.gridwidth = GridBagConstraints.REMAINDER;
		gridBagLayout.setConstraints(usePreviousSecurityCheckBox,
				gridBagConstraints);
		contentPanel.add(usePreviousSecurityCheckBox);

		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy++;
		gridBagConstraints.gridwidth = GridBagConstraints.REMAINDER;
		gridBagLayout.setConstraints(cancelPreviousSecureConversationToken,
				gridBagConstraints);
		contentPanel.add(cancelPreviousSecureConversationToken);

		JPanel expiresPanel = new JPanel();
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy++;
		gridBagConstraints.gridwidth = 2;
		gridBagLayout.setConstraints(expiresPanel, gridBagConstraints);
		contentPanel.add(expiresPanel);

		JLabel expiresLabelLabel = new JLabel(
				"Secure conversation token expires:");
		expiresLabelLabel.setEnabled(null != this.agivSecurity);
		expiresPanel.add(expiresLabelLabel);

		JLabel expiresLabel = new JLabel();
		expiresLabel.setEnabled(null != this.agivSecurity);
		expiresPanel.add(expiresLabel);
		if (null != this.agivSecurity) {
			if (false == this.agivSecurity.getSecureConversationTokens()
					.isEmpty()) {
				SecurityToken secureConversationToken = this.agivSecurity
						.getSecureConversationTokens().values().iterator()
						.next();
				expiresLabel.setText(secureConversationToken.getExpires()
						.toString());
			}
		}

		int dialogResult = JOptionPane.showConfirmDialog(this, contentPanel,
				"Claims Aware Service", JOptionPane.OK_CANCEL_OPTION);
		if (dialogResult == JOptionPane.CANCEL_OPTION) {
			return;
		}

		final String location = urlTextField.getText();
		final String serviceRealm = serviceRealmTextField.getText();
		final String ipStsLocation = ipStsTextField.getText();
		final String rStsLocation = rStsTextField.getText();
		final String username = credentialPanel.getUsername();
		final String password = credentialPanel.getPassword();
		final File pkcs12File = credentialPanel.getPKCS12File();
		final String realm = realmTextField.getText();

		ExecutorService executor = Executors.newFixedThreadPool(1);
		FutureTask<ArrayOfClaimInfo> futureTask = new FutureTask<ArrayOfClaimInfo>(
				new Callable<ArrayOfClaimInfo>() {

					public ArrayOfClaimInfo call() throws Exception {
						Service service;
						if (noWsPolicyCheckBox.isSelected()) {
							service = ClaimsAwareServiceFactory
									.getInstanceNoWSPolicy();
						} else {
							service = ClaimsAwareServiceFactory.getInstance();
						}
						IService iservice = service
								.getWS2007FederationHttpBindingIService(new AddressingFeature());
						BindingProvider bindingProvider = (BindingProvider) iservice;

						if (false == usePreviousSecurityCheckBox.isSelected()) {
							if (null != username) {
								Main.this.agivSecurity = new AGIVSecurity(
										ipStsLocation, rStsLocation, realm,
										username, password);
							} else {
								Main.this.agivSecurity = new AGIVSecurity(
										ipStsLocation, rStsLocation, realm,
										pkcs12File, password);
							}
							Main.this.agivSecurity.addSTSListener(Main.this);
							if (Main.this.proxyEnable) {
								agivSecurity.setProxy(Main.this.proxyHost,
										Main.this.proxyPort,
										Main.this.proxyType);
							}
						}
						if (cancelPreviousSecureConversationToken.isSelected()) {
							Main.this.agivSecurity
									.cancelSecureConversationTokens();
						}
						Main.this.agivSecurity.enable(bindingProvider,
								location,
								useWsSecureConversationCheckBox.isSelected(),
								serviceRealm);

						ArrayOfClaimInfo result = iservice.getData(0);
						return result;
					}
				}) {

			@Override
			protected void done() {
				try {
					ArrayOfClaimInfo result = get();
					List<ClaimInfo> claims = result.getClaimInfo();
					StringBuffer message = new StringBuffer();
					for (ClaimInfo claim : claims) {
						message.append(claim.getName().getValue());
						message.append(" = ");
						message.append(claim.getValue().getValue());
						message.append("\n");
					}

					JOptionPane.showMessageDialog(Main.this,
							message.toString(), "Claims Aware Service Result",
							JOptionPane.INFORMATION_MESSAGE);
				} catch (final Exception e) {
					try {
						SwingUtilities.invokeAndWait(new Runnable() {

							public void run() {
								Main.this.statusBar.setErrorStatus(e
										.getMessage());
							}
						});
					} catch (Exception e1) {
					}
					showException(e);
				}
			}
		};
		executor.execute(futureTask);
	}

	private void ipStsIssueToken() {
		GridBagLayout gridBagLayout = new GridBagLayout();
		GridBagConstraints gridBagConstraints = new GridBagConstraints();
		JPanel contentPanel = new JPanel(gridBagLayout);

		JLabel urlLabel = new JLabel("URL:");
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 0;
		gridBagConstraints.anchor = GridBagConstraints.WEST;
		gridBagConstraints.ipadx = 5;
		gridBagLayout.setConstraints(urlLabel, gridBagConstraints);
		contentPanel.add(urlLabel);

		JTextField urlTextField = new JTextField(
				"https://auth.beta.agiv.be/ipsts/Services/DaliSecurityTokenServiceConfiguration.svc/IWSTrust13",
				60);
		gridBagConstraints.gridx++;
		gridBagLayout.setConstraints(urlTextField, gridBagConstraints);
		contentPanel.add(urlTextField);

		JLabel realmLabel = new JLabel("Realm:");
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy++;
		gridBagLayout.setConstraints(realmLabel, gridBagConstraints);
		contentPanel.add(realmLabel);

		JTextField realmTextField = new JTextField(AGIVSecurity.BETA_REALM, 30);
		gridBagConstraints.gridx++;
		gridBagLayout.setConstraints(realmTextField, gridBagConstraints);
		contentPanel.add(realmTextField);

		CredentialPanel credentialPanel = new CredentialPanel();
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy++;
		gridBagConstraints.gridwidth = GridBagConstraints.REMAINDER;
		gridBagLayout.setConstraints(credentialPanel, gridBagConstraints);
		contentPanel.add(credentialPanel);

		int result = JOptionPane.showConfirmDialog(this, contentPanel,
				"IP-STS Issue Token", JOptionPane.OK_CANCEL_OPTION);
		if (result == JOptionPane.CANCEL_OPTION) {
			return;
		}

		String location = urlTextField.getText();
		String username = credentialPanel.getUsername();
		String password = credentialPanel.getPassword();
		File pkcs12File = credentialPanel.getPKCS12File();
		String realm = realmTextField.getText();

		IPSTSClient ipStsClient = new IPSTSClient(location, realm);
		try {
			if (null != username) {
				this.ipStsSecurityToken = ipStsClient.getSecurityToken(
						username, password);
			} else {
				KeyStore keyStore = KeyStore.getInstance("PKCS12");
				keyStore.load(new FileInputStream(pkcs12File),
						password.toCharArray());
				String alias = keyStore.aliases().nextElement();
				X509Certificate certificate = (X509Certificate) keyStore
						.getCertificate(alias);
				PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias,
						password.toCharArray());
				this.ipStsSecurityToken = ipStsClient.getSecuritytoken(
						certificate, privateKey);
			}
			this.ipStsViewMenuItem.setEnabled(true);
			this.rStsIssueMenuItem.setEnabled(true);
			ipStsViewToken();
		} catch (Exception e) {
			showException(e);
		}
	}

	private void showException(Exception e) {
		StringBuffer stringBuffer = new StringBuffer();
		stringBuffer.append(e.getMessage());
		stringBuffer.append("\n");
		for (StackTraceElement stackTraceElement : e.getStackTrace()) {
			stringBuffer.append(stackTraceElement.getClassName());
			stringBuffer.append(".");
			stringBuffer.append(stackTraceElement.getMethodName());
			stringBuffer.append(":");
			stringBuffer.append(stackTraceElement.getLineNumber());
			stringBuffer.append("\n");
		}
		Throwable cause = e.getCause();
		while (null != cause) {
			stringBuffer.append("\n");
			stringBuffer.append("Caused by: ");
			stringBuffer.append(cause.getMessage());
			stringBuffer.append(" - ");
			stringBuffer.append(cause.getClass().getName());
			stringBuffer.append("\n");
			for (StackTraceElement stackTraceElement : e.getStackTrace()) {
				stringBuffer.append(stackTraceElement.getClassName());
				stringBuffer.append(".");
				stringBuffer.append(stackTraceElement.getMethodName());
				stringBuffer.append(":");
				stringBuffer.append(stackTraceElement.getLineNumber());
				stringBuffer.append("\n");
			}
			cause = cause.getCause();
		}
		JTextArea textArea = new JTextArea(stringBuffer.toString(), 10, 40);
		JScrollPane scrollPane = new JScrollPane(textArea);
		scrollPane.setAutoscrolls(true);
		JOptionPane.showMessageDialog(this, scrollPane, e.getClass()
				.getSimpleName(), JOptionPane.ERROR_MESSAGE);
	}

	private String getVersion() {
		InputStream propertiesInputStream = Main.class
				.getResourceAsStream("/agiv-security-demo.properties");
		if (null == propertiesInputStream) {
			return "unknown";
		}
		Properties properties = new Properties();
		try {
			properties.load(propertiesInputStream);
		} catch (IOException e) {
			LOG.error("error loading properties: " + e.getMessage());
			return "unknown";
		}
		String version = (String) properties.get("version");
		return version;
	}

	public static void main(String[] args) {
		new Main();
	}

	public void requestingIPSTSToken() {
		try {
			SwingUtilities.invokeAndWait(new Runnable() {
				public void run() {
					Main.this.statusBar.setStatus("Requesting IP-STS Token...");
				}
			});
		} catch (Exception e) {
		}
	}

	public void requestingRSTSToken() {
		try {
			SwingUtilities.invokeAndWait(new Runnable() {
				public void run() {
					Main.this.statusBar.setStatus("Requesting R-STS Token...");
				}
			});
		} catch (Exception e) {
		}
	}

	public void requestingSecureConversationToken() {
		try {
			SwingUtilities.invokeAndWait(new Runnable() {
				public void run() {
					Main.this.statusBar
							.setStatus("Requesting Secure Conversation Token...");
				}
			});
		} catch (Exception e) {
		}
	}
}
