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

package test.unit.be.agiv.security.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.InputStream;
import java.security.Key;

import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.conversation.dkalgo.P_SHA1;
import org.apache.ws.security.util.Base64;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.Init;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.Constants;
import org.apache.xpath.XPathAPI;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class SecureConversationClientTest {

	private static final Log LOG = LogFactory
			.getLog(SecureConversationClientTest.class);

	@Test
	public void testCheckSignature() throws Exception {
		Init.init();

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();

		InputStream rStsResponseInputStream = SecureConversationClientTest.class
				.getResourceAsStream("/r-sts-response.xml");
		Document rStsResponse = documentBuilder.parse(rStsResponseInputStream);

		InputStream secConvRequestInputStream = SecureConversationClientTest.class
				.getResourceAsStream("/secure-conversation-request.xml");
		Document secConvRequest = documentBuilder
				.parse(secConvRequestInputStream);
		TestUtils.markAllIdAttributesAsId(secConvRequest);

		Node requestedProofTokenNode = XPathAPI
				.selectSingleNode(
						rStsResponse,
						"soap12:Envelope/soap12:Body/trust:RequestSecurityTokenResponseCollection/trust:RequestSecurityTokenResponse/trust:RequestedProofToken/trust:BinarySecret/text()",
						getNSElement(rStsResponse));
		byte[] requestedProofToken = Base64.decode(requestedProofTokenNode
				.getTextContent());
		LOG.debug("requested proof token size: " + requestedProofToken.length);

		NodeList signatureNodeList = secConvRequest.getElementsByTagNameNS(
				Constants.SignatureSpecNS, "Signature");
		assertEquals(1, signatureNodeList.getLength());
		Element signatureElement = (Element) signatureNodeList.item(0);

		XMLSignature xmlSignature = new XMLSignature(signatureElement, null);
		Key key = WSSecurityUtil.prepareSecretKey(SignatureMethod.HMAC_SHA1,
				requestedProofToken);
		boolean result = xmlSignature.checkSignatureValue(key);

		SignedInfo signedInfo = xmlSignature.getSignedInfo();
		boolean refsResult = signedInfo.verifyReferences();
		assertTrue(refsResult);
		assertTrue(result);

	}
	
	@Test
	public void testCheckClaimsAwareServiceSignature() throws Exception {
		Init.init();

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();

		InputStream secConvRequestInputStream = SecureConversationClientTest.class
				.getResourceAsStream("/secure-conversation-request.xml");
		Document secConvRequest = documentBuilder
				.parse(secConvRequestInputStream);
		
		InputStream secConvResponseInputStream = SecureConversationClientTest.class
				.getResourceAsStream("/secure-conversation-response.xml");
		Document secConvResponse = documentBuilder
				.parse(secConvResponseInputStream);
		
		InputStream requestInputStream = SecureConversationClientTest.class
				.getResourceAsStream("/claims-aware-service-request.xml");
		Document request = documentBuilder
				.parse(requestInputStream);
		TestUtils.markAllIdAttributesAsId(request);

		Node clientEntropyNode = XPathAPI
				.selectSingleNode(
						secConvRequest,
						"soap12:Envelope/soap12:Body/trust:RequestSecurityToken/trust:Entropy/trust:BinarySecret/text()",
						getNSElement(secConvRequest));
		byte[] clientEntropy = Base64.decode(clientEntropyNode
				.getTextContent());
		LOG.debug("client entropy size: " + clientEntropy.length);
		
		Node serverEntropyNode = XPathAPI
				.selectSingleNode(
						secConvResponse,
						"soap12:Envelope/soap12:Body/trust:RequestSecurityTokenResponseCollection/trust:RequestSecurityTokenResponse/trust:Entropy/trust:BinarySecret/text()",
						getNSElement(secConvResponse));
		byte[] serverEntropy = Base64.decode(serverEntropyNode
				.getTextContent());
		LOG.debug("server entropy size: " + serverEntropy.length);

		NodeList signatureNodeList = request.getElementsByTagNameNS(
				Constants.SignatureSpecNS, "Signature");
		assertEquals(1, signatureNodeList.getLength());
		Element signatureElement = (Element) signatureNodeList.item(0);

		XMLSignature xmlSignature = new XMLSignature(signatureElement, null);
		
		P_SHA1 p_SHA1 = new P_SHA1();
		byte[] secretKey = p_SHA1.createKey(clientEntropy, serverEntropy, 0,
				256 / 8);
		LOG.debug("secret key size: " + secretKey.length);
		Key key = WSSecurityUtil.prepareSecretKey(SignatureMethod.HMAC_SHA1,
				secretKey);
		boolean result = xmlSignature.checkSignatureValue(key);

		SignedInfo signedInfo = xmlSignature.getSignedInfo();
		boolean refsResult = signedInfo.verifyReferences();
		assertTrue(refsResult);
		assertTrue(result);

	}

	private Element getNSElement(Document document) {
		Element nsElement = document.createElement("ns");
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
}
