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

import java.util.List;

import javax.xml.ws.BindingProvider;
import javax.xml.ws.soap.AddressingFeature;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Before;
import org.junit.Test;

import be.agiv.security.AGIVSecurity;
import be.agiv.security.crab.edit.jaxb.ArrayOfVerdachtGevalQueryType;
import be.agiv.security.crab.edit.jaxb.VerdachtGevalQueryType;
import be.agiv.security.crab.edit.jaxws.CrabEditService;
import be.agiv.security.crab.edit.jaxws.ICrabEdit;

public class CrabEditTest {

	private static final Log LOG = LogFactory.getLog(CrabEditTest.class);

	private Config config;

	@Before
	public void setUp() throws Exception {
		this.config = new Config();
	}

	@Test
	public void testWebService() throws Exception {
		CrabEditService crabEditService = new CrabEditService();
		ICrabEdit iCrabEdit = crabEditService
				.getWS2007FederationHttpBindingICrabEdit1(new AddressingFeature());

		AGIVSecurity agivSecurity = new AGIVSecurity(
				"https://auth.beta.agiv.be/ipsts/Services/DaliSecurityTokenServiceConfiguration.svc/CertificateMessage",
				"https://auth.beta.agiv.be/sts/Services/SalvadorSecurityTokenServiceConfiguration.svc/IWSTrust13",
				AGIVSecurity.BETA_REALM, this.config.getCertificate(),
				this.config.getPrivateKey());

		BindingProvider bindingProvider = (BindingProvider) iCrabEdit;
		agivSecurity.enable(bindingProvider,
				"https://crab.beta.agiv.be/edit/crabeditservice.svc/wsfed",
				false, "urn:agiv.be/crab/beta");

		ArrayOfVerdachtGevalQueryType verdachteGevallenQuery = iCrabEdit
				.listVerdachteGevallenQueries();
		List<VerdachtGevalQueryType> verdachtGevalList = verdachteGevallenQuery
				.getVerdachtGevalQuery();
		for (VerdachtGevalQueryType verdachtGeval : verdachtGevalList) {
			LOG.debug("verdacht geval: " + verdachtGeval.getQueryId());
		}
	}

	@Test
	public void testWebServiceUsernamePassword() throws Exception {
		CrabEditService crabEditService = new CrabEditService();
		ICrabEdit iCrabEdit = crabEditService
				.getWS2007FederationHttpBindingICrabEdit1(new AddressingFeature());

		AGIVSecurity agivSecurity = new AGIVSecurity(
				"https://auth.beta.agiv.be/ipsts/Services/DaliSecurityTokenServiceConfiguration.svc/IWSTrust13",
				"https://auth.beta.agiv.be/sts/Services/SalvadorSecurityTokenServiceConfiguration.svc/IWSTrust13",
				AGIVSecurity.BETA_REALM, this.config.getUsername(), this.config
						.getPassword());

		BindingProvider bindingProvider = (BindingProvider) iCrabEdit;
		agivSecurity.enable(bindingProvider,
				"https://crab.beta.agiv.be/edit/crabeditservice.svc/wsfed",
				false, "urn:agiv.be/crab/beta");

		ArrayOfVerdachtGevalQueryType verdachteGevallenQuery = iCrabEdit
				.listVerdachteGevallenQueries();
		List<VerdachtGevalQueryType> verdachtGevalList = verdachteGevallenQuery
				.getVerdachtGevalQuery();
		for (VerdachtGevalQueryType verdachtGeval : verdachtGevalList) {
			LOG.debug("verdacht geval: " + verdachtGeval.getQueryId());
		}
	}
}
