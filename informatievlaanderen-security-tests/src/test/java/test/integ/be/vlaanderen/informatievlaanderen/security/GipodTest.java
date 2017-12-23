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
import be.vlaanderen.informatievlaanderen.security.InformatieVlaanderenSecurity;
import be.vlaanderen.informatievlaanderen.security.SecurityToken;
import be.vlaanderen.informatievlaanderen.security.client.RSTSClient;
import be.vlaanderen.informatievlaanderen.security.client.WSConstants;
import be.vlaanderen.informatievlaanderen.security.handler.AuthenticationHandler;
import be.vlaanderen.informatievlaanderen.security.handler.WSSecurityHandler;

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
				.getGipodServiceWsfed(new AddressingFeature());

		InformatieVlaanderenSecurity informatieVlaanderenSecurity = new InformatieVlaanderenSecurity(				
				"https://beta.auth.vlaanderen.be/sts/Services/SalvadorSecurityTokenServiceConfiguration.svc/CertificateMessage",
				this.config.getCertificate(), this.config.getPrivateKey());

		BindingProvider bindingProvider = (BindingProvider) iGipodService;
		informatieVlaanderenSecurity.enable(bindingProvider,
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
}
