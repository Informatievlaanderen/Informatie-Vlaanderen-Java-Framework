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

package be.agiv.security.demo.webapp;

import java.util.List;

import javax.ejb.Stateless;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.WebServiceRef;
import javax.xml.ws.soap.AddressingFeature;

import be.agiv.gipod._2010._06.ArrayOfLand;
import be.agiv.gipod._2010._06.GetListLandResponse;
import be.agiv.gipod._2010._06.Land;
import be.agiv.gipod._2010._06.service.GipodService;
import be.agiv.gipod._2010._06.service.IGipodService;
import be.agiv.gipod._2010._06.service.IGipodServiceGetListLandFaultDetailFaultFaultMessage;
import be.agiv.security.AGIVSecurity;

@Stateless
public class DemoGipodBean {

	@WebServiceRef
	private GipodService service;

	public List<Land> getLanden(DemoCredentials demoCredentials)
			throws DemoGipodException {
		IGipodService iGipodService = this.service
				.getWS2007FederationHttpBindingIGipodService(new AddressingFeature());

		AGIVSecurity agivSecurity = new AGIVSecurity(
				"https://auth.beta.agiv.be/ipsts/Services/DaliSecurityTokenServiceConfiguration.svc/IWSTrust13",
				"https://auth.beta.agiv.be/sts/Services/SalvadorSecurityTokenServiceConfiguration.svc/IWSTrust13",
				AGIVSecurity.BETA_REALM, demoCredentials.getName(),
				demoCredentials.getPassword());

		BindingProvider bindingProvider = (BindingProvider) iGipodService;
		agivSecurity.enable(bindingProvider,
				"https://wsgipod.beta.agiv.be/SOAP/GipodService.svc",
				"urn:agiv.be/gipodbeta");

		GetListLandResponse listLandResponse;
		try {
			listLandResponse = iGipodService.getListLand();
		} catch (IGipodServiceGetListLandFaultDetailFaultFaultMessage e) {
			throw new DemoGipodException();
		} catch (Exception e) {
			throw new DemoGipodException();
		}
		ArrayOfLand landen = listLandResponse.getLanden();
		List<Land> landList = landen.getLand();
		return landList;
	}
}
