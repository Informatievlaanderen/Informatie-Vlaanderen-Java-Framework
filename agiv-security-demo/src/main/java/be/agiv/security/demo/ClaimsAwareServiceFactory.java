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

import java.net.URL;

import javax.xml.namespace.QName;

import org.tempuri.Service;

/**
 * Factory for JAX-WS claims aware service clients.
 * 
 * @author Frank Cornelis
 * 
 */
public class ClaimsAwareServiceFactory {

	public static final String WSDL_RESOURCE = "/ClaimsAwareService.wsdl";

	public static final String WSDL_NO_WS_POLICY_RESOURCE = "/ClaimsAwareService-no-ws-policy.wsdl";

	public static final String SERVICE_LOCATION = "https://auth.beta.agiv.be/ClaimsAwareService/Service.svc/wsfed";
	public static final String SERVICE_SC_LOCATION = "https://auth.beta.agiv.be/ClaimsAwareService/Service.svc/wsfedsc";
	public static final String SERVICE_REALM = "https://auth.beta.agiv.be/ClaimsAwareService/Service.svc";

	private ClaimsAwareServiceFactory() {
		super();
	}

	/**
	 * Creates a new claims aware service client instance.
	 * 
	 * @return a JAX-WS stub.
	 */
	public static Service getInstance() {
		URL wsdlLocation = ClaimsAwareServiceFactory.class
				.getResource(WSDL_RESOURCE);
		if (null == wsdlLocation) {
			throw new RuntimeException("WSDL location not valid: "
					+ WSDL_RESOURCE);
		}
		QName serviceName = new QName("http://tempuri.org/", "Service");
		Service service = new Service(wsdlLocation, serviceName);
		return service;
	}

	/**
	 * Creates a new claims aware service client instance. This instance will
	 * use a local WSDL without WS-Policy configuration.
	 * 
	 * @return a JAX-WS stub.
	 */
	public static Service getInstanceNoWSPolicy() {
		URL wsdlLocation = ClaimsAwareServiceFactory.class
				.getResource(WSDL_NO_WS_POLICY_RESOURCE);
		if (null == wsdlLocation) {
			throw new RuntimeException("WSDL location not valid: "
					+ WSDL_NO_WS_POLICY_RESOURCE);
		}
		QName serviceName = new QName("http://tempuri.org/", "Service");
		Service service = new Service(wsdlLocation, serviceName);
		return service;
	}
}
