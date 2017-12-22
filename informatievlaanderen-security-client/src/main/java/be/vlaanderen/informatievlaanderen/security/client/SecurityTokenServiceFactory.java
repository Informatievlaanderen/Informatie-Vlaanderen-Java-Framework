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

package be.vlaanderen.informatievlaanderen.security.client;

import java.net.URL;

import javax.xml.namespace.QName;

import be.vlaanderen.informatievlaanderen.security.jaxws.wstrust.SecurityTokenService_Service;

/**
 * Factory for the JAX-WS WS-Trust client stub. This factory uses a WSDL that is
 * part of the JAR and is thus platform independent. The client JAR also comes
 * with a JAX-WS catalog to ensure that all required XML schemas can be resolved
 * locally.
 * 
 * @author Frank Cornelis
 * 
 */
public class SecurityTokenServiceFactory {

	public static final String WSDL_RESOURCE = "/ws-trust-1.3.wsdl";

	private SecurityTokenServiceFactory() {
		super();
	}

	/**
	 * Gives back a new instance of the WS-Trust JAX-WS client stub.
	 * 
	 * @return the JAX-WS client stub.
	 */
	public static SecurityTokenService_Service getInstance() {
		URL wsdlLocation = SecurityTokenService_Service.class
				.getResource(WSDL_RESOURCE);
		if (null == wsdlLocation) {
			throw new RuntimeException("WSDL location not valid: "
					+ WSDL_RESOURCE);
		}
		QName serviceName = new QName(
				"http://docs.oasis-open.org/ws-sx/ws-trust/200512",
				"SecurityTokenService");
		SecurityTokenService_Service service = new SecurityTokenService_Service(
				wsdlLocation, serviceName);
		return service;
	}
}
