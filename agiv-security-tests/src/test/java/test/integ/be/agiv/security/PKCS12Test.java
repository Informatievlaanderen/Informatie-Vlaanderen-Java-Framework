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

package test.integ.be.agiv.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

public class PKCS12Test {

	private static final Log LOG = LogFactory.getLog(PKCS12Test.class);

	@Test
	public void testLoadPKCS12() throws Exception {
		Config config = new Config();
		String pkcs12Path = config.getPKCS12Path();
		String pkcs12Password = config.getPKCS12Password();

		InputStream pkcs12InputStream = new FileInputStream(pkcs12Path);
		assertNotNull(pkcs12InputStream);

		LOG.debug("loading PKCS12 keystore");
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(pkcs12InputStream, pkcs12Password.toCharArray());

		Enumeration<String> aliases = keyStore.aliases();
		while (aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			LOG.debug("alias: " + alias);
			X509Certificate certificate = (X509Certificate) keyStore
					.getCertificate(alias);
			LOG.debug("certificate: " + certificate);
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias,
					pkcs12Password.toCharArray());
			LOG.debug("private key algo: " + privateKey.getAlgorithm());
			assertEquals("RSA", privateKey.getAlgorithm());
		}
	}
}
