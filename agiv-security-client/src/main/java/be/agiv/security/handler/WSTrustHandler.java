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

package be.agiv.security.handler;

import java.util.Set;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.transform.TransformerException;
import javax.xml.ws.ProtocolException;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import be.agiv.security.client.WSConstants;

/**
 * A JAX-WS based SOAP handler that implements parts of WS-Trust.
 * <p>
 * This SOAP handler is basically used to retrieve WS-Trust tokens from incoming
 * STS response messages.
 * 
 * @author Frank Cornelis
 * 
 */
public class WSTrustHandler implements AGIVSOAPHandler {

	private final static Log LOG = LogFactory.getLog(WSTrustHandler.class);

	private Element requestedSecurityToken;

	private NodeList secondaryParametersNodeList;

	public boolean handleMessage(SOAPMessageContext context) {
		Boolean outboundProperty = (Boolean) context
				.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		if (false == outboundProperty) {
			try {
				handleInboundMessage(context);
			} catch (Exception e) {
				throw new ProtocolException(e);
			}
		} else {
			try {
				handleOutboundMessage(context);
			} catch (Exception e) {
				LOG.error("error: " + e.getMessage(), e);
				throw new ProtocolException(e);
			}
		}
		return true;
	}

	private void handleOutboundMessage(SOAPMessageContext context)
			throws SOAPException {
		if (null == this.secondaryParametersNodeList) {
			return;
		}
		SOAPMessage soapMessage = context.getMessage();
		SOAPPart soapPart = soapMessage.getSOAPPart();
		SOAPBody soapBody = soapMessage.getSOAPBody();
		NodeList nodeList = soapBody.getElementsByTagNameNS(
				WSConstants.WSTRUST_NAMESPACE, "RequestSecurityToken");
		if (0 == nodeList.getLength()) {
			return;
		}
		SOAPElement requestSecurityTokenElement = (SOAPElement) nodeList
				.item(0);
		String prefix = requestSecurityTokenElement.getPrefix();
		SOAPElement secondaryParametersElement = requestSecurityTokenElement
				.addChildElement("SecondaryParameters", prefix);
		for (int idx = 0; idx < this.secondaryParametersNodeList.getLength(); idx++) {
			Node node = this.secondaryParametersNodeList.item(idx);
			Node importedNode = soapPart.importNode(node, true);
			secondaryParametersElement.appendChild(importedNode);
		}
	}

	private void handleInboundMessage(SOAPMessageContext context)
			throws SOAPException, TransformerException {
		Element bodyElement = context.getMessage().getSOAPBody();

		/*
		 * First tried this via an xalan XPathAPI expression. But we received
		 * some DOM error when using Axis2.
		 */
		NodeList nodeList = bodyElement.getElementsByTagNameNS(
				WSConstants.WSTRUST_NAMESPACE, "RequestedSecurityToken");
		Element requestedSecurityTokenElement;
		if (nodeList.getLength() > 0) {
			requestedSecurityTokenElement = (Element) nodeList.item(0)
					.getFirstChild();
		} else {
			requestedSecurityTokenElement = null;
		}

		this.requestedSecurityToken = requestedSecurityTokenElement;
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
	 * Returns the captured WS-Trust requested security token.
	 * 
	 * @return the token as DOM element.
	 */
	public Element getRequestedSecurityToken() {
		return this.requestedSecurityToken;
	}

	/**
	 * Sets the DOM node list that will be used as SecondaryParameters.
	 * 
	 * @param secondaryParametersNodeList
	 *            a DOM node list.
	 */
	public void setSecondaryParameters(NodeList secondaryParametersNodeList) {
		this.secondaryParametersNodeList = secondaryParametersNodeList;
	}

	/**
	 * Gives back the DOM node list that will be used as SecondaryParameters.
	 * 
	 * @return a DOM node list.
	 */
	public NodeList getSecondaryParameters() {
		return this.secondaryParametersNodeList;
	}
}
