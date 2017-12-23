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
import static org.junit.Assert.assertTrue;

import java.io.InputStream;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
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

import be.vlaanderen.informatievlaanderen.security.InformatieVlaanderenSecurity;
import be.vlaanderen.informatievlaanderen.security.SecurityToken;
import be.vlaanderen.informatievlaanderen.security.client.RSTSClient;
import be.vlaanderen.informatievlaanderen.security.client.SecureConversationClient;
import be.vlaanderen.informatievlaanderen.security.client.WSConstants;
import be.vlaanderen.informatievlaanderen.security.handler.SecureConversationHandler;
import be.vlaanderen.informatievlaanderen.security.handler.SecurityTokenProvider;
import be.vlaanderen.informatievlaanderen.security.handler.WSSecurityHandler;
import be.fedict.commons.eid.jca.BeIDProvider;

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

		InformatieVlaanderenSecurity informatieVlaanderenSecurity = new InformatieVlaanderenSecurity(
				"https://beta.auth.vlaanderen.be/sts/Services/SalvadorSecurityTokenServiceConfiguration.svc/CertificateMessage",
				this.config.getCertificate(),
				this.config.getPrivateKey());

		BindingProvider bindingProvider = (BindingProvider) iCrabRead;
		informatieVlaanderenSecurity.enable(bindingProvider,
				"https://crab.beta.agiv.be/read/crabreadservice.svc/wsfed",
				false, "urn:agiv.be/crab/beta");

		ArrayOfstring gemeentes = iCrabRead.listGemeente();
		List<String> gemeenteList = gemeentes.getString();
		for (String gemeente : gemeenteList) {
			LOG.debug("gemeente: " + gemeente);
		}
		assertTrue(gemeenteList.contains("Vilvoorde"));

		informatieVlaanderenSecurity.refreshSecurityTokens();
	}	

	@Test
	public void testServiceSecureConversation() throws Exception {
		CrabReadService crabReadService = new CrabReadService();

		ICrabRead iCrabRead = crabReadService
				.getWS2007FederationHttpBindingICrabRead(new AddressingFeature());

		InformatieVlaanderenSecurity informatieVlaanderenSecurity = new InformatieVlaanderenSecurity(				
				"https://beta.auth.vlaanderen.be/sts/Services/SalvadorSecurityTokenServiceConfiguration.svc/CertificateMessage",
				this.config.getCertificate(), this.config.getPrivateKey());

		BindingProvider bindingProvider = (BindingProvider) iCrabRead;

		informatieVlaanderenSecurity.enable(bindingProvider, "https://crab.beta.agiv.be/read/crabreadservice.svc/wsfedsc",true, "urn:agiv.be/crab/beta");

		ArrayOfstring gemeentes = iCrabRead.listGemeente();
		List<String> gemeenteList = gemeentes.getString();
		for (String gemeente : gemeenteList) {
			LOG.debug("gemeente: " + gemeente);
		}
		assertTrue(gemeenteList.contains("Vilvoorde"));

		informatieVlaanderenSecurity.refreshSecurityTokens();

		informatieVlaanderenSecurity.cancelSecureConversationTokens();
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
