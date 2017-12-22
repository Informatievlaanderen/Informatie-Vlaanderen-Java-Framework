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

package test.integ.be.vlaanderen.informatievlaanderen.security;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class Config {

	private static final Log LOG = LogFactory.getLog(Config.class);

	private final String username;

	private final String password;

	private final String pkcs12Path;

	private final String pkcs12Password;

	private final X509Certificate certificate;

	private final PrivateKey privateKey;

	public Config() throws IOException, KeyStoreException,
			NoSuchAlgorithmException, CertificateException,
			UnrecoverableKeyException, NoSuchProviderException {
		Properties properties = new Properties();
		properties.load(Config.class.getResourceAsStream("/agiv.properties"));
		this.username = properties.getProperty("username");
		this.password = properties.getProperty("password");
		this.pkcs12Path = properties.getProperty("pkcs12.path");
		this.pkcs12Password = properties.getProperty("pkcs12.password");
		Provider[] providers = Security.getProviders();
		for (Provider provider : providers) {
			LOG.debug("security provider: " + provider.getName());
		}
		if (null != this.pkcs12Path) {
			InputStream pkcs12InputStream = new FileInputStream(pkcs12Path);
			KeyStore keyStore = KeyStore.getInstance("PKCS12", "SunJSSE");
			keyStore.load(pkcs12InputStream, pkcs12Password.toCharArray());
			Enumeration<String> aliases = keyStore.aliases();
			String alias = aliases.nextElement();
			this.certificate = (X509Certificate) keyStore.getCertificate(alias);
			this.privateKey = (PrivateKey) keyStore.getKey(alias,
					this.pkcs12Password.toCharArray());
		} else {
			this.certificate = null;
			this.privateKey = null;
		}
	}

	public String getUsername() {
		return this.username;
	}

	public String getPassword() {
		return this.password;
	}

	public String getPKCS12Path() {
		return this.pkcs12Path;
	}

	public String getPKCS12Password() {
		return this.pkcs12Password;
	}

	public X509Certificate getCertificate() {
		return this.certificate;
	}

	public PrivateKey getPrivateKey() {
		return this.privateKey;
	}
}
