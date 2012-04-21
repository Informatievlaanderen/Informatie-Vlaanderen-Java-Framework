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

package be.agiv.security.demo;

import java.io.File;

import javax.xml.ws.BindingProvider;
import javax.xml.ws.soap.AddressingFeature;

import org.tempuri.IService;
import org.tempuri.Service;

import be.agiv.security.AGIVSecurity;

public class CLIMain {

	private static final String RSTS_LOCATION = "https://auth.beta.agiv.be/sts/Services/SalvadorSecurityTokenServiceConfiguration.svc/IWSTrust13";
	private static final String IPSTS_LOCATION = "https://auth.beta.agiv.be/ipsts/Services/DaliSecurityTokenServiceConfiguration.svc/IWSTrust13";
	private static final String SERVICE_LOCATION = "https://auth.beta.agiv.be/ClaimsAwareService/Service.svc/wsfed";
	private static final String SC_SERVICE_LOCATION = "https://auth.beta.agiv.be/ClaimsAwareService/Service.svc/wsfedsc";
	private static final String IPSTS_CERT_LOCATION = "https://auth.beta.agiv.be/ipsts/Services/DaliSecurityTokenServiceConfiguration.svc/CertificateMessage";
	private static final String SERVICE_REALM = "https://auth.beta.agiv.be/ClaimsAwareService/Service.svc";

	public static void main(String[] args) {
		if (args.length != 4) {
			throw new IllegalArgumentException();
		}
		String username = args[0];
		String password = args[1];
		File pkcs12File = new File(args[2]);
		String pkcs12Password = args[3];

		Service service = ClaimsAwareServiceFactory.getInstanceNoWSPolicy();
		IService iservice = service
				.getWS2007FederationHttpBindingIService(new AddressingFeature());

		AGIVSecurity agivSecurity = new AGIVSecurity(IPSTS_LOCATION,
				RSTS_LOCATION, AGIVSecurity.BETA_REALM, username, password);
		BindingProvider bindingProvider = (BindingProvider) iservice;
		agivSecurity.enable(bindingProvider, SERVICE_LOCATION, SERVICE_REALM);

		iservice.getData(0);

		agivSecurity.disable(bindingProvider);

		agivSecurity.enable(bindingProvider, SC_SERVICE_LOCATION, true,
				SERVICE_REALM);

		iservice.getData(0);

		agivSecurity.disable(bindingProvider);

		agivSecurity = new AGIVSecurity(IPSTS_CERT_LOCATION, RSTS_LOCATION,
				AGIVSecurity.BETA_REALM, pkcs12File, pkcs12Password);

		agivSecurity.enable(bindingProvider, SERVICE_LOCATION, SERVICE_REALM);

		iservice.getData(0);
	}
}
