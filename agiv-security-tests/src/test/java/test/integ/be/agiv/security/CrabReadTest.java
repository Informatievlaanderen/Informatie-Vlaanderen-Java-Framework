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
import static org.junit.Assert.assertTrue;

import java.io.InputStream;
import java.io.StringWriter;
import java.util.List;
import java.util.Properties;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;
import javax.xml.ws.soap.AddressingFeature;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import be.agiv.security.AGIVSecurity;
import be.agiv.security.SecurityToken;
import be.agiv.security.client.IPSTSClient;
import be.agiv.security.client.RSTSClient;
import be.agiv.security.client.SecureConversationClient;
import be.agiv.security.client.WSConstants;
import be.agiv.security.handler.SecureConversationHandler;
import be.agiv.security.handler.SecurityTokenProvider;
import be.agiv.security.handler.WSSecurityHandler;

import com.microsoft.schemas._2003._10.serialization.arrays.ArrayOfstring;

import crabread.crabdecentraal.gisvl.CrabReadService;
import crabread.crabdecentraal.gisvl.ICrabRead;

public class CrabReadTest {

	private static final Log LOG = LogFactory.getLog(CrabReadTest.class);

	private Config config;

	@Before
	public void setUp() throws Exception {
		this.config = new Config();
	}

	@Test
	public void testService() throws Exception {
		CrabReadService crabReadService = new CrabReadService();

		ICrabRead iCrabRead = crabReadService
				.getWS2007FederationHttpBindingICrabRead(new AddressingFeature());

		AGIVSecurity agivSecurity = new AGIVSecurity(
				"https://auth.beta.agiv.be/ipsts/Services/DaliSecurityTokenServiceConfiguration.svc/CertificateMessage",
				"https://auth.beta.agiv.be/sts/Services/SalvadorSecurityTokenServiceConfiguration.svc/IWSTrust13",
				AGIVSecurity.BETA_REALM, this.config.getCertificate(),
				this.config.getPrivateKey());

		BindingProvider bindingProvider = (BindingProvider) iCrabRead;
		agivSecurity.enable(bindingProvider,
				"https://crab.beta.agiv.be/read/crabreadservice.svc/wsfed",
				false, "urn:agiv.be/crab/beta");

		ArrayOfstring gemeentes = iCrabRead.listGemeente();
		List<String> gemeenteList = gemeentes.getString();
		for (String gemeente : gemeenteList) {
			LOG.debug("gemeente: " + gemeente);
		}
		assertTrue(gemeenteList.contains("Vilvoorde"));

		agivSecurity.refreshSecurityTokens();
	}

	@Test
	public void testServiceUsernamePassword() throws Exception {
		CrabReadService crabReadService = new CrabReadService();

		ICrabRead iCrabRead = crabReadService
				.getWS2007FederationHttpBindingICrabRead(new AddressingFeature());

		AGIVSecurity agivSecurity = new AGIVSecurity(
				"https://auth.beta.agiv.be/ipsts/Services/DaliSecurityTokenServiceConfiguration.svc/IWSTrust13",
				"https://auth.beta.agiv.be/sts/Services/SalvadorSecurityTokenServiceConfiguration.svc/IWSTrust13",
				AGIVSecurity.BETA_REALM, this.config.getUsername(), this.config
						.getPassword());

		BindingProvider bindingProvider = (BindingProvider) iCrabRead;
		agivSecurity.enable(bindingProvider,
				"https://crab.beta.agiv.be/read/crabreadservice.svc/wsfed",
				false, "urn:agiv.be/crab/beta");

		ArrayOfstring gemeentes = iCrabRead.listGemeente();
		List<String> gemeenteList = gemeentes.getString();
		for (String gemeente : gemeenteList) {
			LOG.debug("gemeente: " + gemeente);
		}
		assertTrue(gemeenteList.contains("Vilvoorde"));

		agivSecurity.refreshSecurityTokens();
	}

	@Test
	public void testServiceSecureConversation() throws Exception {
		CrabReadService crabReadService = new CrabReadService();

		ICrabRead iCrabRead = crabReadService
				.getWS2007FederationHttpBindingICrabRead(new AddressingFeature());

		AGIVSecurity agivSecurity = new AGIVSecurity(
				"https://auth.beta.agiv.be/ipsts/Services/DaliSecurityTokenServiceConfiguration.svc/CertificateMessage",
				"https://auth.beta.agiv.be/sts/Services/SalvadorSecurityTokenServiceConfiguration.svc/IWSTrust13",
				AGIVSecurity.BETA_REALM, this.config.getCertificate(),
				this.config.getPrivateKey());

		BindingProvider bindingProvider = (BindingProvider) iCrabRead;

		agivSecurity.enable(bindingProvider,
				"https://crab.beta.agiv.be/read/crabreadservice.svc/wsfedsc",
				true, "urn:agiv.be/crab/beta");

		ArrayOfstring gemeentes = iCrabRead.listGemeente();
		List<String> gemeenteList = gemeentes.getString();
		for (String gemeente : gemeenteList) {
			LOG.debug("gemeente: " + gemeente);
		}
		assertTrue(gemeenteList.contains("Vilvoorde"));

		agivSecurity.refreshSecurityTokens();

		agivSecurity.cancelSecureConversationTokens();
	}

	@Test
	public void testIPSTS() throws Exception {
		InputStream wsdlInputStream = CrabReadTest.class
				.getResourceAsStream("/CrabReadService.wsdl");
		assertNotNull(wsdlInputStream);

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document wsdlDocument = documentBuilder.parse(wsdlInputStream);

		NodeList requestSecurityTokenTemplateNodeList = wsdlDocument
				.getElementsByTagNameNS(
						WSConstants.WS_SECURITY_POLICY_NAMESPACE,
						"RequestSecurityTokenTemplate");
		assertEquals(1, requestSecurityTokenTemplateNodeList.getLength());
		Element requestSecurityTokenTemplateElement = (Element) requestSecurityTokenTemplateNodeList
				.item(0);
		LOG.debug("RequestSecurityTokenTemplate: "
				+ toString(requestSecurityTokenTemplateElement));
		NodeList secondaryParametersNodeList = requestSecurityTokenTemplateElement
				.getChildNodes();

		IPSTSClient ipstsClient = new IPSTSClient(
				"https://auth.beta.agiv.be/ipsts/Services/DaliSecurityTokenServiceConfiguration.svc/CertificateMessage",
				AGIVSecurity.BETA_REALM);
		//
		// urn:agiv.be/crab/beta

		SecurityToken ipStsSecurityToken = ipstsClient.getSecuritytoken(
				this.config.getCertificate(), this.config.getPrivateKey());

		RSTSClient rstsClient = new RSTSClient(
				"https://auth.beta.agiv.be/sts/Services/SalvadorSecurityTokenServiceConfiguration.svc/IWSTrust13");
		SecurityToken rStsSecurityToken = rstsClient.getSecurityToken(
				ipStsSecurityToken, "urn:agiv.be/crab/beta");

		LOG.debug("R-STS token received");

		SecureConversationClient secureConversationClient = new SecureConversationClient(
				"http://crab.beta.agiv.be/Read/CrabReadService.svc/wsfedsc");
		SecurityToken secureConversationToken = secureConversationClient
				.getSecureConversationToken(rStsSecurityToken);

		CrabReadService crabReadService = new CrabReadService();
		ICrabRead iCrabRead = crabReadService
				.getWS2007FederationHttpBindingICrabRead(new AddressingFeature());

		BindingProvider bindingProvider = (BindingProvider) iCrabRead;
		bindingProvider.getRequestContext().put(
				BindingProvider.ENDPOINT_ADDRESS_PROPERTY,
				"http://crab.beta.agiv.be/Read/CrabReadService.svc/wsfedsc");

		Binding binding = bindingProvider.getBinding();
		List<Handler> handlerChain = binding.getHandlerChain();

		WSSecurityHandler wsSecurityHandler = new WSSecurityHandler();
		SecureConversationTokenTestProvider secureConversationTokenProvider = new SecureConversationTokenTestProvider(
				secureConversationToken);
		handlerChain.add(new SecureConversationHandler(
				secureConversationTokenProvider, wsSecurityHandler,
				"urn:agiv.be/crab/beta"));
		handlerChain.add(wsSecurityHandler);

		iCrabRead.findStraat("Vilvoorde", "Blaesenbergstraat");
	}

	private static class SecureConversationTokenTestProvider implements
			SecurityTokenProvider {

		private final SecurityToken secureConversationToken;

		public SecureConversationTokenTestProvider(
				SecurityToken secureConversationToken) {
			this.secureConversationToken = secureConversationToken;
		}

		@Override
		public SecurityToken getSecureConversationToken(String location,
				String serviceRealm) {
			return this.secureConversationToken;
		}

		@Override
		public SecurityToken getSecurityToken(String location) {
			return null;
		}
	}

	private String toString(Node node) throws TransformerException {
		StringWriter stringWriter = new StringWriter();
		StreamResult streamResult = new StreamResult(stringWriter);
		Properties properties = new Properties();
		TransformerFactory transformerFactory = TransformerFactory
				.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		transformer.setOutputProperties(properties);
		transformer.transform(new DOMSource(node), streamResult);
		return stringWriter.toString();
	}
}
