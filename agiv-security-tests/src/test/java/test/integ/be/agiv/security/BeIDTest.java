/*
 * AGIV Java Security Project.
 * Copyright (C) 2013 AGIV.
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

import java.io.File;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;

import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;

import be.fedict.commons.eid.jca.BeIDProvider;

public class BeIDTest {

	private static final Log LOG = LogFactory.getLog(BeIDTest.class);

	@Test
	public void testReadAuthnCert() throws Exception {
		Security.addProvider(new BeIDProvider());
		KeyStore keyStore = KeyStore.getInstance("BeID");
		keyStore.load(null);
		Certificate certificate = keyStore.getCertificate("Authentication");
		LOG.debug("certificate: " + certificate);
		Certificate caCert = keyStore.getCertificate("CA");
		LOG.debug("CA cert: " + caCert);
		Certificate rootCert = keyStore.getCertificate("Root");
		LOG.debug("root cert: " + rootCert);

		File tmpFile = File.createTempFile("beid-authn-", ".der");
		FileUtils.writeByteArrayToFile(tmpFile, certificate.getEncoded());
		LOG.debug("cert file: " + tmpFile.getAbsolutePath());

		File caTmpFile = File.createTempFile("gov-ca-", ".der");
		FileUtils.writeByteArrayToFile(caTmpFile, caCert.getEncoded());
		LOG.debug("ca cert file: " + caTmpFile.getAbsolutePath());

		File rootTmpFile = File.createTempFile("root-ca-", ".der");
		FileUtils.writeByteArrayToFile(rootTmpFile, rootCert.getEncoded());
		LOG.debug("root cert file: " + rootTmpFile.getAbsolutePath());
	}
}
