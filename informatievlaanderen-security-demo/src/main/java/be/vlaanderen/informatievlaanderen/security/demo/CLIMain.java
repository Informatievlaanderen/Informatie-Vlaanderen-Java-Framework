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

package be.vlaanderen.informatievlaanderen.security.demo;

import java.io.File;

import javax.xml.ws.BindingProvider;
import javax.xml.ws.soap.AddressingFeature;

import org.tempuri.IService;
import org.tempuri.Service;

import be.vlaanderen.informatievlaanderen.security.InformatieVlaanderenSecurity;

public class CLIMain {

	private static final String RSTS_LOCATION = "https://beta.auth.vlaanderen.be/sts/Services/SalvadorSecurityTokenServiceConfiguration.svc/CertificateMessage";	
	private static final String SERVICE_LOCATION = "https://beta.auth.vlaanderen.be/ClaimsAwareService/Service.svc/wsfed";
	private static final String SC_SERVICE_LOCATION = "https://beta.auth.vlaanderen.be/ClaimsAwareService/Service.svc/wsfedsc";        
	private static final String SERVICE_REALM = "urn:informatievlaanderen.be/claimsawareservice/beta";

	public static void main(String[] args) {
		if (args.length != 2) {
			throw new IllegalArgumentException();
		}		
		File pkcs12File = new File(args[0]);
		String pkcs12Password = args[1];

		Service service = ClaimsAwareServiceFactory.getInstanceNoWSPolicy();
		IService iservice = service
				.getWS2007FederationHttpBindingIService(new AddressingFeature());

		InformatieVlaanderenSecurity informatieVlaanderenSecurity = new InformatieVlaanderenSecurity(RSTS_LOCATION, pkcs12File, pkcs12Password);
		BindingProvider bindingProvider = (BindingProvider) iservice;
		informatieVlaanderenSecurity.enable(bindingProvider, SERVICE_LOCATION, SERVICE_REALM);

		iservice.getData(0);

		informatieVlaanderenSecurity.disable(bindingProvider);

		informatieVlaanderenSecurity.enable(bindingProvider, SC_SERVICE_LOCATION, true,
				SERVICE_REALM);

		iservice.getData(0);		
	}
}
