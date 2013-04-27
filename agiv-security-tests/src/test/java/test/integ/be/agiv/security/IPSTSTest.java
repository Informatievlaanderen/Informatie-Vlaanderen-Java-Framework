/*
 * AGIV Java Security Project.
 * Copyright (C) 2011-2013 AGIV.
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

import be.agiv.security.AGIVSecurity;
import be.agiv.security.SecurityToken;
import be.agiv.security.client.IPSTSClient;
import be.agiv.security.client.RSTSClient;
import be.agiv.security.client.SecureConversationClient;
import be.agiv.security.demo.ClaimsAwareServiceFactory;
import be.fedict.commons.eid.jca.BeIDProvider;

/**
 * Integration tests for the AGIV IP-STS.
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
				"https://auth.beta.agiv.be/ipsts/Services/DaliSecurityTokenServiceConfiguration.svc");

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
	public void testRSTS() throws Exception {
		// setup
		IPSTSClient ipStsClient = new IPSTSClient(
				"https://auth.beta.agiv.be/ipsts/Services/DaliSecurityTokenServiceConfiguration.svc/IWSTrust13",
				AGIVSecurity.BETA_REALM);

		RSTSClient rStsClient = new RSTSClient(
				"https://auth.beta.agiv.be/sts/Services/SalvadorSecurityTokenServiceConfiguration.svc/IWSTrust13");

		// operate
		LOG.debug("IP-STS...");
		SecurityToken ipStsSecurityToken = ipStsClient.getSecurityToken(
				this.config.getUsername(), this.config.getPassword());

		LOG.debug("R-STS...");
		SecurityToken rStsSecurityToken = rStsClient.getSecurityToken(
				ipStsSecurityToken, ClaimsAwareServiceFactory.SERVICE_REALM);

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
		assertEquals(rStsSecurityToken.getParentSecurityToken(),
				ipStsSecurityToken);
	}

	/**
	 * This scenario tests everything related to IP-STS, R-STS and secure
	 * conversations.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testSecureConversation() throws Exception {
		// setup
		IPSTSClient ipStsClient = new IPSTSClient(
				"https://auth.beta.agiv.be/ipsts/Services/DaliSecurityTokenServiceConfiguration.svc/IWSTrust13",
				AGIVSecurity.BETA_REALM);

		RSTSClient rStsClient = new RSTSClient(
				"https://auth.beta.agiv.be/sts/Services/SalvadorSecurityTokenServiceConfiguration.svc/IWSTrust13");

		// operate
		LOG.debug("IP-STS...");
		SecurityToken ipStsSecurityToken = ipStsClient.getSecurityToken(
				this.config.getUsername(), this.config.getPassword());

		LOG.debug("R-STS...");
		SecurityToken rStsSecurityToken = rStsClient.getSecurityToken(
				ipStsSecurityToken, ClaimsAwareServiceFactory.SERVICE_REALM);

		LOG.debug("Secure Conversation...");
		SecureConversationClient secureConversationClient = new SecureConversationClient(
				ClaimsAwareServiceFactory.SERVICE_SC_LOCATION);
		SecurityToken secConvToken = secureConversationClient
				.getSecureConversationToken(rStsSecurityToken);

		// verify
		LOG.debug("SCT created: " + secConvToken.getCreated());
		LOG.debug("SCT expires: " + secConvToken.getExpires());
		assertNotNull(secConvToken.getCreated());
		assertNotNull(secConvToken.getExpires());
		assertNotNull(secConvToken.getKey());
		LOG.debug("SCT attached identifier: "
				+ secConvToken.getAttachedReference());
		LOG.debug("SCT unattached identifier: "
				+ secConvToken.getUnattachedReference());
		assertNotNull(secConvToken.getAttachedReference());
		assertNotNull(secConvToken.getToken());
		assertNotNull(secConvToken.getRealm());
		LOG.debug("SCT realm: " + secConvToken.getRealm());
		assertNotNull(secConvToken.getStsLocation());
		LOG.debug("SCT STS location: " + secConvToken.getStsLocation());
		assertEquals(secConvToken.getParentSecurityToken(), rStsSecurityToken);

		LOG.debug("cancelling secure conversation token...");
		secureConversationClient.cancelSecureConversationToken(secConvToken);

		try {
			secureConversationClient
					.cancelSecureConversationToken(secConvToken);
			fail();
		} catch (SOAPFaultException e) {
			LOG.debug("expected SOAP fault: " + e.getMessage());
		}
	}

	/**
	 * -Dcom.sun.xml.internal.ws.transport.http.client.HttpTransportPipe.dump=
	 * true
	 * 
	 * @throws Exception
	 */
	@Test
	public void testIPSTS() throws Exception {
		// setup
		IPSTSClient client = new IPSTSClient(
				"https://auth.beta.agiv.be/ipsts/Services/DaliSecurityTokenServiceConfiguration.svc/IWSTrust13",
				AGIVSecurity.BETA_REALM);

		// operate
		SecurityToken securityToken = client.getSecurityToken(
				this.config.getUsername(), this.config.getPassword());

		// verify
		assertNotNull(securityToken);
		assertNotNull(securityToken.getKey());
		assertEquals(256 / 8, securityToken.getKey().length);
		LOG.debug("created: " + securityToken.getCreated());
		LOG.debug("expired: " + securityToken.getExpires());
		assertNotNull(securityToken.getCreated());
		assertNotNull(securityToken.getExpires());
		assertNotNull(securityToken.getToken());
		assertEquals("EncryptedData", securityToken.getToken().getLocalName());
		LOG.debug("token identifier: " + securityToken.getAttachedReference());
		assertNotNull(securityToken.getAttachedReference());
		assertNotNull(securityToken.getRealm());
		LOG.debug("realm: " + securityToken.getRealm());
		assertNotNull(securityToken.getStsLocation());
		LOG.debug("STS location: " + securityToken.getStsLocation());
		assertNull(securityToken.getParentSecurityToken());
	}

	@Test
	public void testIPSTSCertificate() throws Exception {
		// setup
		IPSTSClient client = new IPSTSClient(
				"https://auth.beta.agiv.be/ipsts/Services/DaliSecurityTokenServiceConfiguration.svc/CertificateMessage",
				AGIVSecurity.BETA_REALM);

		// operate
		SecurityToken securityToken = client.getSecuritytoken(
				this.config.getCertificate(), this.config.getPrivateKey());

		// verify
		assertNotNull(securityToken);
		assertNotNull(securityToken.getKey());
		assertEquals(256 / 8, securityToken.getKey().length);
		LOG.debug("created: " + securityToken.getCreated());
		LOG.debug("expired: " + securityToken.getExpires());
		assertNotNull(securityToken.getCreated());
		assertNotNull(securityToken.getExpires());
		assertNotNull(securityToken.getToken());
		assertEquals("EncryptedData", securityToken.getToken().getLocalName());
		LOG.debug("token identifier: " + securityToken.getAttachedReference());
		assertNotNull(securityToken.getAttachedReference());
	}

	@Test
	public void testIPSTS_BeIDCertificate() throws Exception {
		Security.addProvider(new BeIDProvider());
		KeyStore keyStore = KeyStore.getInstance("BeID");
		keyStore.load(null);
		PrivateKey privateKey = (PrivateKey) keyStore.getKey("Authentication",
				null);
		X509Certificate certificate = (X509Certificate) keyStore
				.getCertificate("Authentication");
		assertNotNull(privateKey);
		assertNotNull(certificate);

		// setup
		IPSTSClient client = new IPSTSClient(
				"https://auth.beta.agiv.be/ipsts/Services/DaliSecurityTokenServiceConfiguration.svc/CertificateMessage",
				AGIVSecurity.BETA_REALM);

		// operate
		SecurityToken securityToken = client.getSecuritytoken(certificate,
				privateKey);

		// verify
		assertNotNull(securityToken);
		assertNotNull(securityToken.getKey());
		assertEquals(256 / 8, securityToken.getKey().length);
		LOG.debug("created: " + securityToken.getCreated());
		LOG.debug("expired: " + securityToken.getExpires());
		assertNotNull(securityToken.getCreated());
		assertNotNull(securityToken.getExpires());
		assertNotNull(securityToken.getToken());
		assertEquals("EncryptedData", securityToken.getToken().getLocalName());
		LOG.debug("token identifier: " + securityToken.getAttachedReference());
		assertNotNull(securityToken.getAttachedReference());
	}

	@Test
	public void testIPSTSCancelToken() throws Exception {
		// setup
		IPSTSClient client = new IPSTSClient(
				"https://auth.beta.agiv.be/ipsts/Services/DaliSecurityTokenServiceConfiguration.svc/IWSTrust13",
				AGIVSecurity.BETA_REALM);

		// operate
		SecurityToken securityToken = client.getSecurityToken(
				this.config.getUsername(), this.config.getPassword());

		LOG.debug("attached reference: " + securityToken.getAttachedReference());
		LOG.debug("unattached reference: "
				+ securityToken.getUnattachedReference());

		client.cancelSecurityToken(securityToken);
	}

	/**
	 * According to the documentation, the R-STS can also behave as an IP-STS
	 * for issuing of tokens.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testRSTS_BehavingAs_IPSTS() throws Exception {
		// setup
		IPSTSClient client = new IPSTSClient(
				"https://auth.beta.agiv.be/sts/Services/SalvadorSecurityTokenServiceConfiguration.svc/UserName",
				AGIVSecurity.BETA_REALM);

		// operate
		SecurityToken securityToken = client.getSecurityToken(
				this.config.getUsername(), this.config.getPassword());

		// verify
		assertNotNull(securityToken);
		assertNotNull(securityToken.getKey());
		assertEquals(256 / 8, securityToken.getKey().length);
		LOG.debug("created: " + securityToken.getCreated());
		LOG.debug("expired: " + securityToken.getExpires());
		assertNotNull(securityToken.getCreated());
		assertNotNull(securityToken.getExpires());
		assertNotNull(securityToken.getToken());
		assertEquals("EncryptedData", securityToken.getToken().getLocalName());
		LOG.debug("token identifier: " + securityToken.getAttachedReference());
		assertNotNull(securityToken.getAttachedReference());
	}

	@Test
	public void testSTS_JAXWS_Client() throws Exception {
		ServletTester servletTester = new ServletTester();
		servletTester.addServlet(MyTestServlet.class, "/");

		Security.addProvider(new BouncyCastleProvider());

		KeyPair keyPair = generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = generateSelfSignedCertificate(keyPair,
				"CN=localhost", notBefore, notAfter);
		File tmpP12File = File.createTempFile("ssl-", ".p12");
		LOG.debug("p12 file: " + tmpP12File.getAbsolutePath());
		persistKey(tmpP12File, keyPair.getPrivate(), certificate,
				"secret".toCharArray(), "secret".toCharArray());

		SslSocketConnector sslSocketConnector = new SslSocketConnector();
		sslSocketConnector.setKeystore(tmpP12File.getAbsolutePath());
		sslSocketConnector.setTruststore(tmpP12File.getAbsolutePath());
		sslSocketConnector.setTruststoreType("pkcs12");
		sslSocketConnector.setKeystoreType("pkcs12");
		sslSocketConnector.setPassword("secret");
		sslSocketConnector.setKeyPassword("secret");
		sslSocketConnector.setTrustPassword("secret");
		sslSocketConnector.setMaxIdleTime(30000);
		int sslPort = getFreePort();
		sslSocketConnector.setPort(sslPort);

		servletTester.getContext().getServer().addConnector(sslSocketConnector);
		String sslLocation = "https://localhost:" + sslPort + "/";

		servletTester.start();
		String location = servletTester.createSocketConnector(true);

		SSLContext sslContext = SSLContext.getInstance("TLS");
		TrustManager trustManager = new TestTrustManager(certificate);
		sslContext.init(null, new TrustManager[] { trustManager }, null);
		SSLContext.setDefault(sslContext);

		try {
			LOG.debug("running IP-STS test...");
			IPSTSClient client = new IPSTSClient(sslLocation,
					AGIVSecurity.BETA_REALM);
			client.getSecurityToken("username", "password");
		} finally {
			servletTester.stop();
		}
	}

	@Test
	public void testRSTS_JAXWS_Client() throws Exception {
		ServletTester servletTester = new ServletTester();
		servletTester.addServlet(MyTestServlet.class, "/");

		Security.addProvider(new BouncyCastleProvider());

		KeyPair keyPair = generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = generateSelfSignedCertificate(keyPair,
				"CN=localhost", notBefore, notAfter);
		File tmpP12File = File.createTempFile("ssl-", ".p12");
		LOG.debug("p12 file: " + tmpP12File.getAbsolutePath());
		persistKey(tmpP12File, keyPair.getPrivate(), certificate,
				"secret".toCharArray(), "secret".toCharArray());

		SslSocketConnector sslSocketConnector = new SslSocketConnector();
		sslSocketConnector.setKeystore(tmpP12File.getAbsolutePath());
		sslSocketConnector.setTruststore(tmpP12File.getAbsolutePath());
		sslSocketConnector.setTruststoreType("pkcs12");
		sslSocketConnector.setKeystoreType("pkcs12");
		sslSocketConnector.setPassword("secret");
		sslSocketConnector.setKeyPassword("secret");
		sslSocketConnector.setTrustPassword("secret");
		sslSocketConnector.setMaxIdleTime(30000);
		int sslPort = getFreePort();
		sslSocketConnector.setPort(sslPort);

		servletTester.getContext().getServer().addConnector(sslSocketConnector);
		String sslLocation = "https://localhost:" + sslPort + "/";

		servletTester.start();
		String location = servletTester.createSocketConnector(true);

		SSLContext sslContext = SSLContext.getInstance("TLS");
		TrustManager trustManager = new TestTrustManager(certificate);
		sslContext.init(null, new TrustManager[] { trustManager }, null);
		SSLContext.setDefault(sslContext);

		try {
			LOG.debug("running R-STS test...");
			RSTSClient client = new RSTSClient(sslLocation);
			SecurityToken inputSecurityToken = new SecurityToken();
			byte[] key = new byte[256 / 8];
			SecureRandom random = new SecureRandom();
			random.nextBytes(key);
			inputSecurityToken.setKey(key);
			inputSecurityToken.setAttachedReference("_"
					+ UUID.randomUUID().toString());
			DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
					.newInstance();
			documentBuilderFactory.setNamespaceAware(true);
			DocumentBuilder documentBuilder = documentBuilderFactory
					.newDocumentBuilder();
			Document document = documentBuilder.newDocument();
			Element tokenElement = document.createElement("Token");
			tokenElement.setTextContent("hello world");
			inputSecurityToken.setToken(tokenElement);

			client.getSecurityToken(inputSecurityToken,
					"https://auth.beta.agiv.be/ClaimsAwareService/Service.svc");
		} finally {
			servletTester.stop();
		}
	}

	private KeyPair generateKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = new SecureRandom();
		keyPairGenerator.initialize(new RSAKeyGenParameterSpec(1024,
				RSAKeyGenParameterSpec.F4), random);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}

	private X509Certificate generateSelfSignedCertificate(KeyPair keyPair,
			String subjectDn, DateTime notBefore, DateTime notAfter)
			throws IOException, InvalidKeyException, IllegalStateException,
			NoSuchAlgorithmException, SignatureException, CertificateException {
		PublicKey subjectPublicKey = keyPair.getPublic();
		PrivateKey issuerPrivateKey = keyPair.getPrivate();
		String signatureAlgorithm = "SHA1WithRSAEncryption";
		X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
		certificateGenerator.reset();
		certificateGenerator.setPublicKey(subjectPublicKey);
		certificateGenerator.setSignatureAlgorithm(signatureAlgorithm);
		certificateGenerator.setNotBefore(notBefore.toDate());
		certificateGenerator.setNotAfter(notAfter.toDate());
		X509Principal issuerDN = new X509Principal(subjectDn);
		certificateGenerator.setIssuerDN(issuerDN);
		certificateGenerator.setSubjectDN(new X509Principal(subjectDn));
		certificateGenerator.setSerialNumber(new BigInteger(128,
				new SecureRandom()));

		certificateGenerator.addExtension(X509Extensions.SubjectKeyIdentifier,
				false, createSubjectKeyId(subjectPublicKey));
		PublicKey issuerPublicKey;
		issuerPublicKey = subjectPublicKey;
		certificateGenerator.addExtension(
				X509Extensions.AuthorityKeyIdentifier, false,
				createAuthorityKeyId(issuerPublicKey));

		certificateGenerator.addExtension(X509Extensions.BasicConstraints,
				false, new BasicConstraints(true));

		X509Certificate certificate;
		certificate = certificateGenerator.generate(issuerPrivateKey);

		/*
		 * Next certificate factory trick is needed to make sure that the
		 * certificate delivered to the caller is provided by the default
		 * security provider instead of BouncyCastle. If we don't do this trick
		 * we might run into trouble when trying to use the CertPath validator.
		 */
		CertificateFactory certificateFactory = CertificateFactory
				.getInstance("X.509");
		certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(certificate
						.getEncoded()));
		return certificate;
	}

	private static int getFreePort() throws Exception {
		ServerSocket serverSocket = new ServerSocket(0);
		int port = serverSocket.getLocalPort();
		serverSocket.close();
		return port;
	}

	private SubjectKeyIdentifier createSubjectKeyId(PublicKey publicKey)
			throws IOException {
		ByteArrayInputStream bais = new ByteArrayInputStream(
				publicKey.getEncoded());
		SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
				(ASN1Sequence) new ASN1InputStream(bais).readObject());
		return new SubjectKeyIdentifier(info);
	}

	private AuthorityKeyIdentifier createAuthorityKeyId(PublicKey publicKey)
			throws IOException {

		ByteArrayInputStream bais = new ByteArrayInputStream(
				publicKey.getEncoded());
		SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
				(ASN1Sequence) new ASN1InputStream(bais).readObject());

		return new AuthorityKeyIdentifier(info);
	}

	private void persistKey(File pkcs12keyStore, PrivateKey privateKey,
			X509Certificate certificate, char[] keyStorePassword,
			char[] keyEntryPassword) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore keyStore = KeyStore.getInstance("pkcs12");
		keyStore.load(null, keyStorePassword);
		keyStore.setKeyEntry("default", privateKey, keyEntryPassword,
				new Certificate[] { certificate });
		FileOutputStream keyStoreOut = new FileOutputStream(pkcs12keyStore);
		keyStore.store(keyStoreOut, keyStorePassword);
		keyStoreOut.close();
	}

	private static class TestTrustManager implements X509TrustManager {

		private final X509Certificate serverCertificate;

		public TestTrustManager(X509Certificate serverCertificate) {
			this.serverCertificate = serverCertificate;
		}

		public void checkClientTrusted(X509Certificate[] chain, String authnType)
				throws CertificateException {
			throw new CertificateException("not implemented");
		}

		public void checkServerTrusted(X509Certificate[] chain, String authnType)
				throws CertificateException {
			if (false == this.serverCertificate.equals(chain[0])) {
				throw new CertificateException("server certificate not trusted");
			}
		}

		public X509Certificate[] getAcceptedIssuers() {
			return null;
		}
	}
}
