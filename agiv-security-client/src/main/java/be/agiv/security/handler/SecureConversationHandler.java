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
 * A JAX-WS based WS-SecureConversation SOAP handler.
 * <p/>
 * This JAX-WS handler adds a WS-Security SOAP header using a secure
 * conversation token that it retrieves from the AGIV Security component.
 * Basically this JAX-WS handler configures a downstream WS-Security JAX-WS
 * handler using a secure conversation token.
 * 
 * @author Frank Cornelis
 * 
 */
public class SecureConversationHandler implements AGIVSOAPHandler,
		SecurityTokenConsumer {

	private static final Log LOG = LogFactory
			.getLog(SecureConversationHandler.class);

	private final SecurityTokenProvider securityTokenProvider;

	private final WSSecurityHandler wsSecurityHandler;

	private final String serviceRealm;

	/**
	 * Main constructor.
	 * 
	 * @param securityTokenProvider
	 *            the AGIV Security component from which to retrieve the secure
	 *            conversation tokens to be used during web service calls.
	 * @param wsSecurityHandler
	 *            the WS-Security handler.
	 * @param serviceRealm
	 *            the optional service realm.
	 */
	public SecureConversationHandler(
			SecurityTokenProvider securityTokenProvider,
			WSSecurityHandler wsSecurityHandler, String serviceRealm) {
		this.securityTokenProvider = securityTokenProvider;
		this.wsSecurityHandler = wsSecurityHandler;
		this.serviceRealm = serviceRealm;
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
		String location = (String) context
				.get(BindingProvider.ENDPOINT_ADDRESS_PROPERTY);
		LOG.debug("location: " + location);

		String serviceRealm;
		if (null != this.serviceRealm) {
			serviceRealm = this.serviceRealm;
		} else {
			serviceRealm = location;
		}
		LOG.debug("service realm: " + serviceRealm);

		SecurityToken secureConversationToken = this.securityTokenProvider
				.getSecureConversationToken(location, serviceRealm);

		this.wsSecurityHandler.setKey(secureConversationToken.getKey(),
				secureConversationToken.getAttachedReference(),
				secureConversationToken.getToken(), false);
	}

	public boolean handleFault(SOAPMessageContext context) {
		return true;
	}

	public void close(MessageContext context) {
	}

	public Set<QName> getHeaders() {
		return null;
	}
}
