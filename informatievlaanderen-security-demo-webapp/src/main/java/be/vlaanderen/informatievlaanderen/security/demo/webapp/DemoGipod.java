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

package be.vlaanderen.informatievlaanderen.security.demo.webapp;

import java.io.Serializable;
import java.util.List;

import javax.ejb.EJB;
import javax.enterprise.context.ConversationScoped;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.inject.Named;

import be.agiv.gipod._2010._06.Land;

@Named
@ConversationScoped
public class DemoGipod implements Serializable {

	private static final long serialVersionUID = 1L;

	@Inject
	private DemoCredentials demoCredentials;

	@EJB
	private DemoGipodBean demoGipodBean;

	private List<Land> landenList;

	public String invoke() {
		try {
			this.landenList = this.demoGipodBean
					.getLanden(this.demoCredentials);
		} catch (DemoGipodException e) {
			FacesContext.getCurrentInstance().addMessage(null,
					new FacesMessage("error invoking GIPOD web service"));
		}
		return "/result";
	}

	public List<Land> getLandenList() {
		return this.landenList;
	}
}
