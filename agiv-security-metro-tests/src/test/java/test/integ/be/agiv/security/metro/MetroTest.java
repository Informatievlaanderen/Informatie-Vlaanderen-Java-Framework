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

package test.integ.be.agiv.security.metro;

import static org.junit.Assert.*;

import java.net.URL;

import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.soap.AddressingFeature;
import javax.xml.ws.spi.Provider;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;
import be.agiv.security.jaxws.wstrust.SecurityTokenService_Service;
import org.tempuri.IService;
import org.tempuri.Service;

public class MetroTest {

	private static final Log LOG = LogFactory.getLog(MetroTest.class);

	@Test
	public void testProvider() throws Exception {
		Provider provider = Provider.provider();
		LOG.debug("provider class: " + provider.getClass().getName());
		assertEquals("com.sun.xml.ws.spi.ProviderImpl", provider.getClass()
				.getName());
	}
	
	@Test
	public void testClaimsAwareService() {
		URL wsdlLocation = SecurityTokenService_Service.class
				.getResource("/ClaimsAwareService-metro.wsdl");
		QName serviceName = new QName("http://tempuri.org/", "Service");
		Service service = new Service(wsdlLocation, serviceName);
		// WS-Addressing via JAX-WS
		IService iservice = service
				.getWS2007FederationHttpBindingIService(new AddressingFeature());

		BindingProvider bindingProvider = (BindingProvider) iservice;
		bindingProvider.getRequestContext().put(
				BindingProvider.ENDPOINT_ADDRESS_PROPERTY,
				"https://beta.auth.vlaanderen.be/ClaimsAwareService/Service.svc");

		LOG.debug("calling getData");
		iservice.getData(0);
	}
}
