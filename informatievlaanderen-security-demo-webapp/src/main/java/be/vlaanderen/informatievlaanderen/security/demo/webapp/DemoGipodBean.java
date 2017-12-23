/*
 * Informatie Vlaanderen Java Security Project.
 * Copyright (C) 2011-2012 Informatie Vlaanderen.
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

package be.vlaanderen.informatievlaanderen.security.demo.webapp;

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
import be.vlaanderen.informatievlaanderen.security.InformatieVlaanderenSecurity;

@Stateless
public class DemoGipodBean {

	@WebServiceRef
	private GipodService service;

	public List<Land> getLanden(DemoCredentials demoCredentials)
			throws DemoGipodException {
		IGipodService iGipodService = this.service
				.getGipodServiceWsfed(new AddressingFeature());

		InformatieVlaanderenSecurity informatieVlaanderenSecurity = new InformatieVlaanderenSecurity(				
				"https://beta.auth.vlaanderen.be/sts/Services/SalvadorSecurityTokenServiceConfiguration.svc/IWSTrust13",
				demoCredentials.getCertificate(),demoCredentials.getPrivateKey());

		BindingProvider bindingProvider = (BindingProvider) iGipodService;
		informatieVlaanderenSecurity.enable(bindingProvider,
				"https://service.beta.gipod.vlaanderen.be/soap/GipodService.svc",
				"urn:informatievlaanderen.be/gipod/service/beta");

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
