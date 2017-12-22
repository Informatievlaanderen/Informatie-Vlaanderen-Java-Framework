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

package test.unit.be.agiv.security.handler;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Properties;
import java.util.UUID;

import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPConstants;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.ws.ProtocolException;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecTimestamp;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.Constants;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.easymock.EasyMock;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import test.unit.be.agiv.security.client.TestUtils;
import be.agiv.security.handler.WSAddressingHandler;
import be.agiv.security.handler.WSSecurityHandler;

import com.sun.org.apache.xpath.internal.XPathAPI;

public class WSSecurityHandlerTest {

	private static final Log LOG = LogFactory
			.getLog(WSSecurityHandlerTest.class);

	private WSSecurityHandler testedInstance;

	@BeforeClass
	public static void registerBouncyCastle() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Before
	public void setUp() throws Exception {
		this.testedInstance = new WSSecurityHandler();
	}

	@Test
	public void testVerifyTimestampExpired() throws Exception {
		// setup
		SOAPMessageContext mockContext = EasyMock
				.createMock(SOAPMessageContext.class);

		EasyMock.expect(
				mockContext.get("javax.xml.ws.handler.message.outbound"))
				.andStubReturn(Boolean.FALSE);

		InputStream requestInputStream = WSSecurityHandlerTest.class
				.getResourceAsStream("/ip-sts-response.xml");
		SOAPMessage soapMessage = MessageFactory.newInstance(
				SOAPConstants.SOAP_1_2_PROTOCOL).createMessage(null,
				requestInputStream);
		EasyMock.expect(mockContext.getMessage()).andStubReturn(soapMessage);

		// prepare
		EasyMock.replay(mockContext);

		// operate
		try {
			this.testedInstance.handleMessage(mockContext);
			fail();
		} catch (ProtocolException e) {
			// verify
			EasyMock.verify(mockContext);
		}
	}

	@Test
	public void testVerifyTimestamp() throws Exception {
		// setup
		SOAPMessageContext mockContext = EasyMock
				.createMock(SOAPMessageContext.class);

		EasyMock.expect(
				mockContext.get("javax.xml.ws.handler.message.outbound"))
				.andStubReturn(Boolean.FALSE);

		SOAPMessage soapMessage = MessageFactory.newInstance(
				SOAPConstants.SOAP_1_2_PROTOCOL).createMessage();

		SOAPBody soapBody = soapMessage.getSOAPBody();
		soapBody.addBodyElement(new QName("test"));

		SOAPPart soapPart = soapMessage.getSOAPPart();
		WSSecHeader secHeader = new WSSecHeader();
		secHeader.insertSecurityHeader(soapPart);
		WSSecTimestamp timestamp = new WSSecTimestamp();
		timestamp.build(soapPart, secHeader);

		LOG.debug("SOAP message: " + toString(soapMessage.getSOAPPart()));
		EasyMock.expect(mockContext.getMessage()).andStubReturn(soapMessage);

		// prepare
		EasyMock.replay(mockContext);

		// operate
		boolean result = this.testedInstance.handleMessage(mockContext);

		// verify
		EasyMock.verify(mockContext);
		assertTrue(result);
	}

	@Test
	public void testVerifyTimestampMissing() throws Exception {
		// setup
		SOAPMessageContext mockContext = EasyMock
				.createMock(SOAPMessageContext.class);

		EasyMock.expect(
				mockContext.get("javax.xml.ws.handler.message.outbound"))
				.andStubReturn(Boolean.FALSE);

		SOAPMessage soapMessage = MessageFactory.newInstance(
				SOAPConstants.SOAP_1_2_PROTOCOL).createMessage();

		SOAPBody soapBody = soapMessage.getSOAPBody();
		soapBody.addBodyElement(new QName("test"));

		LOG.debug("SOAP message: " + toString(soapMessage.getSOAPPart()));
		EasyMock.expect(mockContext.getMessage()).andStubReturn(soapMessage);

		// prepare
		EasyMock.replay(mockContext);

		// operate
		try {
			this.testedInstance.handleMessage(mockContext);
			fail();
		} catch (ProtocolException e) {
			// verify
			EasyMock.verify(mockContext);
		}
	}

	@Test
	public void testSignature() throws Exception {
		// setup
		SOAPMessageContext mockContext = EasyMock
				.createMock(SOAPMessageContext.class);

		EasyMock.expect(
				mockContext.get("javax.xml.ws.handler.message.outbound"))
				.andStubReturn(Boolean.TRUE);

		byte[] secret = new byte[256 / 8];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(secret);

		String tokenIdentifier = "#saml-token-test";
		this.testedInstance.setKey(secret, tokenIdentifier, null, false);

		InputStream requestInputStream = WSSecurityHandlerTest.class
				.getResourceAsStream("/r-sts-request-before-signing.xml");
		SOAPMessage soapMessage = MessageFactory.newInstance(
				SOAPConstants.SOAP_1_2_PROTOCOL).createMessage(null,
				requestInputStream);
		EasyMock.expect(mockContext.getMessage()).andStubReturn(soapMessage);

		// prepare
		EasyMock.replay(mockContext);

		// operate
		boolean result = this.testedInstance.handleMessage(mockContext);

		// verify
		EasyMock.verify(mockContext);
		assertTrue(result);

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		soapMessage.writeTo(outputStream);
		LOG.debug("SOAP message: " + new String(outputStream.toByteArray()));

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(
				outputStream.toByteArray());
		Document resultDocument = documentBuilder.parse(byteArrayInputStream);
		TestUtils.markAllIdAttributesAsId(resultDocument);

		NodeList signatureNodeList = resultDocument.getElementsByTagNameNS(
				Constants.SignatureSpecNS, "Signature");
		assertEquals(1, signatureNodeList.getLength());
		Element signatureElement = (Element) signatureNodeList.item(0);

		XMLSignature xmlSignature = new XMLSignature(signatureElement, null);
		Key key = WSSecurityUtil.prepareSecretKey(SignatureMethod.HMAC_SHA1,
				secret);
		boolean signatureResult = xmlSignature.checkSignatureValue(key);
		assertTrue(signatureResult);

		LOG.debug("signed SOAP: " + toString(resultDocument));
	}

	@Test
	public void testCertificateSignature() throws Exception {
		// setup
		SOAPMessageContext mockContext = EasyMock
				.createMock(SOAPMessageContext.class);

		EasyMock.expect(
				mockContext.get("javax.xml.ws.handler.message.outbound"))
				.andStubReturn(Boolean.TRUE);

		SOAPMessage soapMessage = MessageFactory
				.newInstance(SOAPConstants.SOAP_1_2_PROTOCOL)
				.createMessage(
						null,
						new ByteArrayInputStream(
								("<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
										+ "<soap:Header>"
										+ "<wsa:To soap:mustUnderstand=\"1\" wsu:Id=\"toId\">destination</wsa:To>"
										+ "</soap:Header>"
										+ "<soap:Body>test</soap:Body>"
										+ "</soap:Envelope>").getBytes()));
		EasyMock.expect(mockContext.getMessage()).andStubReturn(soapMessage);

		EasyMock.expect(
				mockContext.get(WSAddressingHandler.class.getName() + ".toId"))
				.andStubReturn("toId");

		KeyPair keyPair = generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();

		X509Certificate certificate = generateSelfSignedCertificate(keyPair);
		this.testedInstance.setCredentials(privateKey, certificate);

		// prepare
		EasyMock.replay(mockContext);

		// operate
		boolean result = this.testedInstance.handleMessage(mockContext);

		// verify
		EasyMock.verify(mockContext);
		assertTrue(result);

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		soapMessage.writeTo(outputStream);
		LOG.debug("SOAP message: " + new String(outputStream.toByteArray()));

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(
				outputStream.toByteArray());
		Document resultDocument = documentBuilder.parse(byteArrayInputStream);
		TestUtils.markAllIdAttributesAsId(resultDocument);

		NodeList signatureNodeList = resultDocument.getElementsByTagNameNS(
				Constants.SignatureSpecNS, "Signature");
		assertEquals(1, signatureNodeList.getLength());
		Element signatureElement = (Element) signatureNodeList.item(0);

		XMLSignature xmlSignature = new XMLSignature(signatureElement, null);
		boolean signatureResult = xmlSignature.checkSignatureValue(certificate);
		assertTrue(signatureResult);

		LOG.debug("signed SOAP: " + toString(resultDocument));
	}

	@Test
	public void testUsernameToken() throws Exception {
		// setup
		WSSecurityHandler testedInstance = new WSSecurityHandler();

		SOAPMessageContext mockContext = EasyMock
				.createMock(SOAPMessageContext.class);

		EasyMock.expect(
				mockContext.get("javax.xml.ws.handler.message.outbound"))
				.andStubReturn(Boolean.TRUE);
		String testUsername = "username-" + UUID.randomUUID().toString();

		testedInstance.setCredentials(testUsername, "password");

		SOAPMessage soapMessage = MessageFactory
				.newInstance(SOAPConstants.SOAP_1_1_PROTOCOL)
				.createMessage(
						null,
						new ByteArrayInputStream(
								"<Envelope xmlns=\"http://schemas.xmlsoap.org/soap/envelope/\"><Body>test</Body></Envelope>"
										.getBytes()));

		LOG.debug("SOAP message: " + toString(soapMessage.getSOAPPart()));
		EasyMock.expect(mockContext.getMessage()).andStubReturn(soapMessage);

		// prepare
		EasyMock.replay(mockContext);

		// operate
		testedInstance.handleMessage(mockContext);

		// verify
		EasyMock.verify(mockContext);
		LOG.debug("SOAP message after handleMessage: "
				+ toString(soapMessage.getSOAPPart()));

		Element nsElement = getNSElement(soapMessage.getSOAPPart());
		String resultUsername = XPathAPI
				.selectSingleNode(
						soapMessage.getSOAPPart(),
						"soap:Envelope/soap:Header/wsse:Security/wsse:UsernameToken/wsse:Username/text()",
						nsElement).getNodeValue();
		assertEquals(testUsername, resultUsername);
	}

	private Element getNSElement(Document document) {
		Element nsElement = document.createElement("ns");
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:soap",
				"http://schemas.xmlsoap.org/soap/envelope/");
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:soap12",
				"http://www.w3.org/2003/05/soap-envelope");
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:trust",
				"http://docs.oasis-open.org/ws-sx/ws-trust/200512");
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:xenc",
				"http://www.w3.org/2001/04/xmlenc#");
		nsElement
				.setAttributeNS(
						Constants.NamespaceSpecNS,
						"xmlns:wsse",
						"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
		nsElement
				.setAttributeNS(
						Constants.NamespaceSpecNS,
						"xmlns:wsu",
						"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
		return nsElement;
	}

	private KeyPair generateKeyPair() throws Exception {
		return generateKeyPair(1024);
	}

	private KeyPair generateKeyPair(int keySize) throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = new SecureRandom();
		keyPairGenerator.initialize(new RSAKeyGenParameterSpec(keySize,
				RSAKeyGenParameterSpec.F4), random);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}

	private X509Certificate generateSelfSignedCertificate(KeyPair keyPair)
			throws Exception {
		X500Name issuer = new X500Name("CN=Test");
		X500Name subject = issuer;

		SecureRandom secureRandom = new SecureRandom();
		byte[] serialValue = new byte[8];
		secureRandom.nextBytes(serialValue);
		BigInteger serial = new BigInteger(serialValue);

		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);

		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo
				.getInstance(keyPair.getPublic().getEncoded());

		X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(
				issuer, serial, notBefore.toDate(), notAfter.toDate(), subject,
				publicKeyInfo);

		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
				.find("SHA1withRSA");
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
				.find(sigAlgId);
		AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory
				.createKey(keyPair.getPrivate().getEncoded());
		ContentSigner contentSigner = new BcRSAContentSignerBuilder(sigAlgId,
				digAlgId).build(asymmetricKeyParameter);
		X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder
				.build(contentSigner);

		byte[] encodedCertificate = x509CertificateHolder.getEncoded();

		CertificateFactory certificateFactory = CertificateFactory
				.getInstance("X.509");
		X509Certificate certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(
						encodedCertificate));
		return certificate;
	}

	@Test
	public void testWSSecurityWithoutInitialHeader() throws Exception {
		// setup
		SOAPMessageContext mockContext = EasyMock
				.createMock(SOAPMessageContext.class);

		EasyMock.expect(
				mockContext.get("javax.xml.ws.handler.message.outbound"))
				.andStubReturn(Boolean.TRUE);
		EasyMock.expect(
				mockContext
						.get("be.agiv.security.handler.WSSecurityHandler.token"))
				.andStubReturn(null);
		EasyMock.expect(
				mockContext
						.get("be.agiv.security.handler.WSSecurityHandler.username"))
				.andStubReturn("username");
		EasyMock.expect(
				mockContext
						.get("be.agiv.security.handler.WSSecurityHandler.password"))
				.andStubReturn("password");
		EasyMock.expect(
				mockContext
						.get("be.agiv.security.handler.WSSecurityHandler.key"))
				.andStubReturn(null);

		SOAPMessage soapMessage = MessageFactory
				.newInstance(SOAPConstants.SOAP_1_2_PROTOCOL)
				.createMessage(
						null,
						new ByteArrayInputStream(
								"<Envelope xmlns=\"http://www.w3.org/2003/05/soap-envelope\"><Body>test</Body></Envelope>"
										.getBytes()));

		LOG.debug("SOAP message: " + toString(soapMessage.getSOAPPart()));
		EasyMock.expect(mockContext.getMessage()).andStubReturn(soapMessage);

		EasyMock.expect(
				mockContext.get(WSSecurityHandler.class.getName()
						+ ".certificate")).andStubReturn(null);

		// prepare
		EasyMock.replay(mockContext);

		// operate
		this.testedInstance.handleMessage(mockContext);

		// verify
		EasyMock.verify(mockContext);
	}

	private String toString(Document document) throws TransformerException {
		StringWriter stringWriter = new StringWriter();
		StreamResult streamResult = new StreamResult(stringWriter);
		Properties properties = new Properties();
		properties.put(OutputKeys.METHOD, "html");
		properties.put(OutputKeys.INDENT, "5");
		TransformerFactory transformerFactory = TransformerFactory
				.newInstance();
		Transformer transformer = null;
		transformer = transformerFactory.newTransformer();
		transformer.setOutputProperties(properties);
		transformer.transform(new DOMSource(document), streamResult);
		return stringWriter.toString();
	}
}