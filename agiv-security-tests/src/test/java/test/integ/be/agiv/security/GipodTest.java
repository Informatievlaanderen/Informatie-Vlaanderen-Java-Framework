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

import java.io.InputStream;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
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
import org.w3c.dom.NodeList;

import be.agiv.gipod._2010._06.ArrayOfLand;
import be.agiv.gipod._2010._06.GetListLandResponse;
import be.agiv.gipod._2010._06.Land;
import be.agiv.gipod._2010._06.service.GipodService;
import be.agiv.gipod._2010._06.service.IGipodService;
import be.agiv.security.AGIVSecurity;
import be.agiv.security.SecurityToken;
import be.agiv.security.client.IPSTSClient;
import be.agiv.security.client.RSTSClient;
import be.agiv.security.client.WSConstants;
import be.agiv.security.handler.AuthenticationHandler;
import be.agiv.security.handler.WSSecurityHandler;

public class GipodTest {

	private static final Log LOG = LogFactory.getLog(GipodTest.class);

	private Config config;

	@Before
	public void setUp() throws Exception {
		this.config = new Config();
	}

	@Test
	public void testGipod() throws Exception {
		GipodService service = new GipodService();

		IGipodService iGipodService = service
				.getWS2007FederationHttpBindingIGipodService(new AddressingFeature());

		AGIVSecurity agivSecurity = new AGIVSecurity(
				"https://auth.beta.agiv.be/ipsts/Services/DaliSecurityTokenServiceConfiguration.svc/IWSTrust13",
				"https://auth.beta.agiv.be/sts/Services/SalvadorSecurityTokenServiceConfiguration.svc/IWSTrust13",
				AGIVSecurity.BETA_REALM, this.config.getUsername(), this.config
						.getPassword());

		BindingProvider bindingProvider = (BindingProvider) iGipodService;
		agivSecurity.enable(bindingProvider,
				"https://gipod.beta.agiv.be/webservice/GIPODService.svc/wsfed",
				"urn:agiv.be/gipodbeta");

		LOG.debug("calling GIPOD service");
		GetListLandResponse listLandResponse = iGipodService.getListLand();
		ArrayOfLand landen = listLandResponse.getLanden();
		List<Land> landList = landen.getLand();
		for (Land land : landList) {
			LOG.debug("land: " + land.getCode() + " " + land.getNaam());
		}
	}

	@Test
	public void testGipodManualSecurity() throws Exception {
		InputStream wsdlInputStream = CrabReadTest.class
				.getResourceAsStream("/GipodService.wsdl");
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
		NodeList secondaryParametersNodeList = requestSecurityTokenTemplateElement
				.getChildNodes();

		IPSTSClient ipstsClient = new IPSTSClient(
				"https://auth.beta.agiv.be/ipsts/Services/DaliSecurityTokenServiceConfiguration.svc/IWSTrust13",
				AGIVSecurity.BETA_REALM, secondaryParametersNodeList);

		SecurityToken ipStsSecurityToken = ipstsClient.getSecurityToken(
				this.config.getUsername(), this.config.getPassword());

		RSTSClient rstsClient = new RSTSClient(
				"https://auth.beta.agiv.be/sts/Services/SalvadorSecurityTokenServiceConfiguration.svc/IWSTrust13");
		SecurityToken rStsSecurityToken = rstsClient.getSecurityToken(
				ipStsSecurityToken, "urn:agiv.be/gipodbeta");
		// "https://wsgipod.beta.agiv.be/SOAP/GipodService.svc");

		WSSecurityHandler wsSecurityHandler = new WSSecurityHandler();
		TestSecurityTokenProvider securityTokenProvider = new TestSecurityTokenProvider();
		securityTokenProvider.addSecurityToken(
				"https://wsgipod.beta.agiv.be/SOAP/GipodService.svc",
				rStsSecurityToken);
		AuthenticationHandler authenticationHandler = new AuthenticationHandler(
				securityTokenProvider, wsSecurityHandler, null);

		GipodService service = new GipodService();
		IGipodService iGipodService = service
				.getWS2007FederationHttpBindingIGipodService(new AddressingFeature());

		BindingProvider bindingProvider = (BindingProvider) iGipodService;
		bindingProvider.getRequestContext().put(
				BindingProvider.ENDPOINT_ADDRESS_PROPERTY,
				"https://wsgipod.beta.agiv.be/SOAP/GipodService.svc");
		Binding binding = bindingProvider.getBinding();
		List<Handler> handlerChain = binding.getHandlerChain();
		handlerChain.add(authenticationHandler);
		handlerChain.add(wsSecurityHandler);
		binding.setHandlerChain(handlerChain);

		iGipodService.getListLand();
	}
}
