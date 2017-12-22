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

package test.unit.be.vlaanderen.informatievlaanderen.security.client;

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

public class RSTSClientTest {

	private static final Log LOG = LogFactory.getLog(RSTSClientTest.class);

	@Test
	public void testSignatureWCF() throws Exception {
		checkSignature("/ip-sts-request.xml", "/ip-sts-response.xml",
				"/r-sts-request.xml");
	}

	@Test
	public void testSignatureJava() throws Exception {
		checkSignature("/ip-sts-request-java.xml", "/ip-sts-response-java.xml",
				"/r-sts-request-java.xml");
	}

	private void checkSignature(String ipStsRequestResource,
			String ipStsResponseResource, String rStsRequestResource)
			throws Exception {
		Init.init();

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();

		InputStream ipStsRequestInputStream = RSTSClientTest.class
				.getResourceAsStream(ipStsRequestResource);
		Document ipStsRequest = documentBuilder.parse(ipStsRequestInputStream);

		InputStream ipStsResponseInputStream = RSTSClientTest.class
				.getResourceAsStream(ipStsResponseResource);
		Document ipStsResponse = documentBuilder
				.parse(ipStsResponseInputStream);

		InputStream rStsRequestInputStream = RSTSClientTest.class
				.getResourceAsStream(rStsRequestResource);
		Document rStsRequest = documentBuilder.parse(rStsRequestInputStream);
		TestUtils.markAllIdAttributesAsId(rStsRequest);

		Node clientEntropyNode = XPathAPI
				.selectSingleNode(
						ipStsRequest,
						"soap12:Envelope/soap12:Body/trust:RequestSecurityToken/trust:Entropy/trust:BinarySecret/text()",
						getNSElement(ipStsRequest));
		byte[] clientEntropy = Base64
				.decode(clientEntropyNode.getTextContent());
		LOG.debug("client entropy size: " + clientEntropy.length);

		Node serverEntropyNode = XPathAPI
				.selectSingleNode(
						ipStsResponse,
						"soap12:Envelope/soap12:Body/trust:RequestSecurityTokenResponseCollection/trust:RequestSecurityTokenResponse/trust:Entropy/trust:BinarySecret/text()",
						getNSElement(ipStsResponse));
		byte[] serverEntropy = Base64
				.decode(serverEntropyNode.getTextContent());
		LOG.debug("server entropy size: " + serverEntropy.length);

		NodeList signatureNodeList = rStsRequest.getElementsByTagNameNS(
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
