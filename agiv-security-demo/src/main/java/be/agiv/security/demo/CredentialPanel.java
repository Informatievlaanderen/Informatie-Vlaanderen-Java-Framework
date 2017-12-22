/*
 * Informatie Vlaanderen Java Security Project.
 * Copyright (C) 2011-2017 Informatie Vlaanderen.
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

import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.filechooser.FileFilter;

/**
 * Generic Swing Credential Panel. Used for selecting the different AGIV
 * credentials: username/password or X509 certificate.
 * 
 * @author Frank Cornelis
 * 
 */
public class CredentialPanel extends JPanel implements ActionListener {

	private static final long serialVersionUID = 1L;

	private final JTextField usernameTextField;

	private final JPasswordField userPasswordField;

	private final JRadioButton usernameRadioButton;

	private final JRadioButton certificateRadioButton;

	private final JLabel usernameLabel;

	private final JLabel userPasswordLabel;

	private final JLabel pkcs12PathLabel;

	private final JTextField pkcs12PathTextField;

	private final JLabel pkcs12PasswordLabel;

	private final JPasswordField pkcs12PasswordField;

	private final JButton pkcs12BrowseButton;

	public CredentialPanel() {
		GridBagLayout gridBagLayout = new GridBagLayout();
		GridBagConstraints gridBagConstraints = new GridBagConstraints();
		setLayout(gridBagLayout);
		setBorder(BorderFactory.createTitledBorder("AGIV Credential"));

		this.usernameRadioButton = new JRadioButton("Username/password");
		this.usernameRadioButton.addActionListener(this);
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 0;
		gridBagConstraints.gridwidth = GridBagConstraints.REMAINDER;
		gridBagConstraints.anchor = GridBagConstraints.WEST;
		gridBagLayout.setConstraints(this.usernameRadioButton,
				gridBagConstraints);
		add(this.usernameRadioButton);

		Component indentBox = Box.createHorizontalStrut(30);
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy++;
		gridBagConstraints.gridwidth = 1;
		gridBagLayout.setConstraints(indentBox, gridBagConstraints);
		add(indentBox);

		{
			GridBagLayout usernameGridBagLayout = new GridBagLayout();
			GridBagConstraints usernameGridBagConstraints = new GridBagConstraints();
			JPanel usernamePanel = new JPanel(usernameGridBagLayout);
			gridBagConstraints.gridx++;
			gridBagLayout.setConstraints(usernamePanel, gridBagConstraints);
			add(usernamePanel);

			this.usernameLabel = new JLabel("Username:");
			usernameGridBagConstraints.gridx = 0;
			usernameGridBagConstraints.gridy = 0;
			usernameGridBagConstraints.anchor = GridBagConstraints.WEST;
			usernameGridBagConstraints.ipadx = 5;
			usernameGridBagLayout.setConstraints(this.usernameLabel,
					usernameGridBagConstraints);
			usernamePanel.add(this.usernameLabel);

			this.usernameTextField = new JTextField(15);
			usernameGridBagConstraints.gridx++;
			usernameGridBagLayout.setConstraints(this.usernameTextField,
					usernameGridBagConstraints);
			usernamePanel.add(this.usernameTextField);

			this.userPasswordLabel = new JLabel("Password:");
			usernameGridBagConstraints.gridx = 0;
			usernameGridBagConstraints.gridy++;
			usernameGridBagLayout.setConstraints(this.userPasswordLabel,
					usernameGridBagConstraints);
			usernamePanel.add(this.userPasswordLabel);

			this.userPasswordField = new JPasswordField(15);
			usernameGridBagConstraints.gridx++;
			usernameGridBagLayout.setConstraints(this.userPasswordField,
					usernameGridBagConstraints);
			usernamePanel.add(this.userPasswordField);
		}

		this.certificateRadioButton = new JRadioButton("Certificate");
		this.certificateRadioButton.addActionListener(this);
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy++;
		gridBagConstraints.gridwidth = GridBagConstraints.REMAINDER;
		gridBagLayout.setConstraints(this.certificateRadioButton,
				gridBagConstraints);
		add(this.certificateRadioButton);

		{
			GridBagLayout certificateGridBagLayout = new GridBagLayout();
			GridBagConstraints certificateGridBagConstraints = new GridBagConstraints();
			JPanel certificatePanel = new JPanel(certificateGridBagLayout);
			gridBagConstraints.gridx = 1;
			gridBagConstraints.gridy++;
			gridBagLayout.setConstraints(certificatePanel, gridBagConstraints);
			add(certificatePanel);

			this.pkcs12PathLabel = new JLabel("PKCS#12 path:");
			certificateGridBagConstraints.gridx = 0;
			certificateGridBagConstraints.gridy = 0;
			certificateGridBagConstraints.anchor = GridBagConstraints.WEST;
			certificateGridBagConstraints.ipadx = 5;
			certificateGridBagLayout.setConstraints(this.pkcs12PathLabel,
					certificateGridBagConstraints);
			certificatePanel.add(this.pkcs12PathLabel);

			this.pkcs12PathTextField = new JTextField(40);
			certificateGridBagConstraints.gridx++;
			certificateGridBagLayout.setConstraints(this.pkcs12PathTextField,
					certificateGridBagConstraints);
			certificatePanel.add(this.pkcs12PathTextField);

			this.pkcs12BrowseButton = new JButton("Browse...");
			this.pkcs12BrowseButton.addActionListener(this);
			certificateGridBagConstraints.gridx++;
			certificateGridBagLayout.setConstraints(this.pkcs12BrowseButton,
					certificateGridBagConstraints);
			certificatePanel.add(this.pkcs12BrowseButton);

			this.pkcs12PasswordLabel = new JLabel("Password:");
			certificateGridBagConstraints.gridx = 0;
			certificateGridBagConstraints.gridy++;
			certificateGridBagLayout.setConstraints(this.pkcs12PasswordLabel,
					certificateGridBagConstraints);
			certificatePanel.add(this.pkcs12PasswordLabel);

			this.pkcs12PasswordField = new JPasswordField(30);
			certificateGridBagConstraints.gridx++;
			certificateGridBagLayout.setConstraints(this.pkcs12PasswordField,
					certificateGridBagConstraints);
			certificatePanel.add(this.pkcs12PasswordField);
		}

		ButtonGroup buttonGroup = new ButtonGroup();
		buttonGroup.add(this.usernameRadioButton);
		buttonGroup.add(this.certificateRadioButton);

		updateEnableState();
	}

	public String getUsername() {
		if (this.usernameRadioButton.isSelected()) {
			return this.usernameTextField.getText();
		}
		return null;
	}

	public String getPassword() {
		if (this.usernameRadioButton.isSelected()) {
			return new String(this.userPasswordField.getPassword());
		}
		if (this.certificateRadioButton.isSelected()) {
			return new String(this.pkcs12PasswordField.getPassword());
		}
		return null;
	}

	public File getPKCS12File() {
		if (this.certificateRadioButton.isSelected()) {
			return new File(this.pkcs12PathTextField.getText());
		}
		return null;
	}

	public void actionPerformed(ActionEvent e) {
		Object source = e.getSource();
		if (this.usernameRadioButton == source) {
			updateEnableState();
		} else if (this.certificateRadioButton == source) {
			updateEnableState();
		} else if (this.pkcs12BrowseButton == source) {
			selectKeyStoreFile();
		}
	}

	private void selectKeyStoreFile() {
		JFileChooser fileChooser = new JFileChooser();
		FileFilter filter = new FileFilter() {

			@Override
			public boolean accept(File file) {
				if (file.isDirectory()) {
					return true;
				}
				String fileName = file.getName();
				if (fileName.endsWith(".p12")) {
					return true;
				}
				if (fileName.endsWith(".pfx")) {
					return true;
				}
				return false;
			}

			@Override
			public String getDescription() {
				return "PKCS#12 Files";
			}
		};
		fileChooser.setFileFilter(filter);
		int result = fileChooser.showOpenDialog(this);
		if (JFileChooser.APPROVE_OPTION == result) {
			File selectedFile = fileChooser.getSelectedFile();
			this.pkcs12PathTextField.setText(selectedFile.getAbsolutePath());
		}
	}

	private void updateEnableState() {
		boolean usernameEnable = this.usernameRadioButton.isSelected();
		this.usernameLabel.setEnabled(usernameEnable);
		this.usernameTextField.setEnabled(usernameEnable);
		this.userPasswordLabel.setEnabled(usernameEnable);
		this.userPasswordField.setEnabled(usernameEnable);

		boolean certEnable = this.certificateRadioButton.isSelected();
		this.pkcs12PathLabel.setEnabled(certEnable);
		this.pkcs12PathTextField.setEnabled(certEnable);
		this.pkcs12PasswordLabel.setEnabled(certEnable);
		this.pkcs12PasswordField.setEnabled(certEnable);
		this.pkcs12BrowseButton.setEnabled(certEnable);
	}

	@Override
	public void setEnabled(boolean enabled) {
		super.setEnabled(enabled);
		this.usernameRadioButton.setEnabled(enabled);
		this.certificateRadioButton.setEnabled(enabled);
		if (false == enabled) {
			this.usernameLabel.setEnabled(enabled);
			this.usernameTextField.setEnabled(enabled);
			this.userPasswordLabel.setEnabled(enabled);
			this.userPasswordField.setEnabled(enabled);
			this.pkcs12PathLabel.setEnabled(enabled);
			this.pkcs12PathTextField.setEnabled(enabled);
			this.pkcs12PasswordLabel.setEnabled(enabled);
			this.pkcs12PasswordField.setEnabled(enabled);
			this.pkcs12BrowseButton.setEnabled(enabled);
		} else {
			updateEnableState();
		}
	}
}
