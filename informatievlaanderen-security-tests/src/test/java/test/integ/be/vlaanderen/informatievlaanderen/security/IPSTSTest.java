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

import test.integ.be.vlaanderen.informatievlaanderen.security.Config;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Enumeration;
import java.util.UUID;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.ws.soap.SOAPFaultException;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mortbay.jetty.security.SslSocketConnector;
import org.mortbay.jetty.testing.ServletTester;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import be.vlaanderen.informatievlaanderen.security.InformatieVlaanderenSecurity;
import be.vlaanderen.informatievlaanderen.security.SecurityToken;
import be.vlaanderen.informatievlaanderen.security.client.RSTSClient;
import be.vlaanderen.informatievlaanderen.security.client.SecureConversationClient;
import be.vlaanderen.informatievlaanderen.security.demo.ClaimsAwareServiceFactory;
import be.fedict.commons.eid.jca.BeIDProvider;

/**
 * Integration tests for the Informatie Vlaanderen IP-STS.
 * 
 * @author Frank Cornelis
 * 
 */
public class IPSTSTest {

	private static final Log LOG = LogFactory.getLog(IPSTSTest.class);

	private Config config;

	@BeforeClass
	public static void beforeClass() {
		// required for PEMReader
		Security.addProvider(new BouncyCastleProvider());
	}

	@Before
	public void setUp() throws Exception {
		this.config = new Config();
	}

	/**
	 * Checks whether the IP-STS is up and running.
	 */
	@Test
	public void testAlive() throws Exception {
		// setup
		HttpClient httpClient = new DefaultHttpClient();
		HttpGet httpget = new HttpGet(
				"https://beta.auth.vlaanderen.be/ipsts/Services/DaliSecurityTokenServiceConfiguration.svc");

		// operate
		HttpResponse response = httpClient.execute(httpget);

		// verify
		StatusLine statusLine = response.getStatusLine();
		int statusCode = statusLine.getStatusCode();
		LOG.debug("status code: " + statusCode);
		assertEquals(HttpStatus.SC_OK, statusCode);
	}

	public static final class MyTestServlet extends HttpServlet {

		private static final long serialVersionUID = 1L;

		private static final Log LOG = LogFactory.getLog(MyTestServlet.class);

		@Override
		protected void doPost(HttpServletRequest request,
				HttpServletResponse response) throws ServletException,
				IOException {
			LOG.debug("doPost");
			Enumeration headerNames = request.getHeaderNames();
			while (headerNames.hasMoreElements()) {
				String headerName = (String) headerNames.nextElement();
				String headerValue = request.getHeader(headerName);
				LOG.debug(headerName + ": " + headerValue);
			}
			InputStream inputStream = request.getInputStream();
			String body = IOUtils.toString(inputStream);
			LOG.debug("body: " + body);
			File tmpFile = File.createTempFile("ip-sts-request-", ".xml");
			FileUtils.write(tmpFile, body);
			LOG.debug("tmp file: " + tmpFile.getAbsolutePath());
			Runtime runtime = Runtime.getRuntime();
			runtime.exec(new String[] { "firefox", tmpFile.getAbsolutePath() });
		}
	}
	
	@Test
	public void testRSTSGIPOD() throws Exception {
		// setup
		RSTSClient rStsClient = new RSTSClient("https://beta.auth.vlaanderen.be/sts/Services/SalvadorSecurityTokenServiceConfiguration.svc/CertificateMessage");

		// operate
		LOG.debug("R-STS...");
		SecurityToken rStsSecurityToken = rStsClient.getSecurityToken(
				config.getCertificate(),config.getPrivateKey(), "urn:informatievlaanderen.be/gipod/service/beta");

		// verify
		assertNotNull(rStsSecurityToken);
		assertNotNull(rStsSecurityToken.getToken());
		assertNotNull(rStsSecurityToken.getKey());
		LOG.debug("created: " + rStsSecurityToken.getCreated());
		LOG.debug("expired: " + rStsSecurityToken.getExpires());
		assertNotNull(rStsSecurityToken.getCreated());
		assertNotNull(rStsSecurityToken.getExpires());
		LOG.debug("token identifier: "
				+ rStsSecurityToken.getAttachedReference());
		assertNotNull(rStsSecurityToken.getAttachedReference());
		assertNotNull(rStsSecurityToken.getRealm());
		LOG.debug("realm: " + rStsSecurityToken.getRealm());
		assertNotNull(rStsSecurityToken.getStsLocation());
		LOG.debug("STS location: " + rStsSecurityToken.getStsLocation());		
	}


	@Test
	public void testRSTS() throws Exception {
		// setup
		RSTSClient rStsClient = new RSTSClient(
				"https://beta.auth.vlaanderen.be/sts/Services/SalvadorSecurityTokenServiceConfiguration.svc/CertificateMessage");

		LOG.debug("R-STS...");
		SecurityToken rStsSecurityToken = rStsClient.getSecurityToken(
				config.getCertificate(),config.getPrivateKey(), ClaimsAwareServiceFactory.SERVICE_REALM);

		// verify
		assertNotNull(rStsSecurityToken);
		assertNotNull(rStsSecurityToken.getToken());
		assertNotNull(rStsSecurityToken.getKey());
		LOG.debug("created: " + rStsSecurityToken.getCreated());
		LOG.debug("expired: " + rStsSecurityToken.getExpires());
		assertNotNull(rStsSecurityToken.getCreated());
		assertNotNull(rStsSecurityToken.getExpires());
		LOG.debug("token identifier: "
				+ rStsSecurityToken.getAttachedReference());
		assertNotNull(rStsSecurityToken.getAttachedReference());
		assertNotNull(rStsSecurityToken.getRealm());
		LOG.debug("realm: " + rStsSecurityToken.getRealm());
		assertNotNull(rStsSecurityToken.getStsLocation());
		LOG.debug("STS location: " + rStsSecurityToken.getStsLocation());		
	}	
}
