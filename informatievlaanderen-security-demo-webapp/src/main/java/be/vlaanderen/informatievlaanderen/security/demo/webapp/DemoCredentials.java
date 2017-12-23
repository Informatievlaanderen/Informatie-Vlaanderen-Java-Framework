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
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.enterprise.context.ConversationScoped;
import javax.inject.Named;

@Named
@ConversationScoped
public class DemoCredentials implements Serializable {

	private static final long serialVersionUID = 1L;

	private X509Certificate certificate;

	private PrivateKey privatekey;

	public X509Certificate getCertificate() {
		return this.certificate;
	}

	public void setCertificate(X509Certificate certificate) {
		this.certificate = certificate;
	}

	public PrivateKey getPrivateKey() {
		return this.privatekey;
	}

	public void setPassword(PrivateKey privateKey) {
		this.privatekey = privateKey;
	}
}
