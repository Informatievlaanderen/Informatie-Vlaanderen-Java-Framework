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

package be.agiv.security.handler;

import java.util.Set;

import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.ProtocolException;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.agiv.security.SecurityToken;

/**
 * A JAX-WS SOAP handler that provides web service authentication via a security
 * token.
 * 
 * @author Frank Cornelis
 * 
 */
public class AuthenticationHandler implements AGIVSOAPHandler,
		SecurityTokenConsumer {

	private static final Log LOG = LogFactory
			.getLog(AuthenticationHandler.class);

	private final SecurityTokenProvider securityTokenProvider;

	private final WSSecurityHandler wsSecurityHandler;

	private final String serviceRealm;

	/**
	 * Main Constructor.
	 * <p/>
	 * If no service realm is specified, the service location will be used as
	 * service realm towards the R-STS.
	 * 
	 * @param securityTokenProvider
	 *            the AGIV Security component from which to retrieve the
	 *            security token to be used during web service calls.
	 * @param wsSecurityHandler
	 *            the WS-Security handler.
	 * @param serviceRealm
	 *            the optional service realm.
	 */
	public AuthenticationHandler(SecurityTokenProvider securityTokenProvider,
			WSSecurityHandler wsSecurityHandler, String serviceRealm) {
		this.securityTokenProvider = securityTokenProvider;
		this.wsSecurityHandler = wsSecurityHandler;
		this.serviceRealm = serviceRealm;
	}

	public boolean handleMessage(SOAPMessageContext context) {
		Boolean outboundProperty = (Boolean) context
				.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);

		if (true == outboundProperty.booleanValue()) {
			try {
				handleOutboundMessage(context);
			} catch (Exception e) {
				throw new ProtocolException(e);
			}
		}

		return true;
	}

	private void handleOutboundMessage(SOAPMessageContext context) {
		String serviceRealm;
		if (null != this.serviceRealm) {
			serviceRealm = this.serviceRealm;
		} else {
			String location = (String) context
					.get(BindingProvider.ENDPOINT_ADDRESS_PROPERTY);
			serviceRealm = location;
		}
		LOG.debug("service realm: " + serviceRealm);

		SecurityToken securityToken = this.securityTokenProvider
				.getSecurityToken(serviceRealm);

		this.wsSecurityHandler.setKey(securityToken.getKey(),
				securityToken.getAttachedReference(), securityToken.getToken(),
				true);
	}

	public boolean handleFault(SOAPMessageContext context) {
		return true;
	}

	public void close(MessageContext context) {
	}

	public Set<QName> getHeaders() {
		return null;
	}

	/**
	 * Gives back the security token provider instance that this handler will
	 * use to acquire security tokens.
	 * 
	 * @return the security token provider instance.
	 */
	public SecurityTokenProvider getSecurityTokenProvider() {
		return this.securityTokenProvider;
	}
}
