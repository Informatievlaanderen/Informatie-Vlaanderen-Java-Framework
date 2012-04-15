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

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.UUID;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFactory;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import javax.xml.ws.ProtocolException;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.agiv.security.client.WSConstants;
import be.agiv.security.jaxb.wsaddr.ObjectFactory;
import be.agiv.security.jaxb.wsaddr.RelatesToType;

/**
 * A JAX-WS SOAP handler that implements the WS-Addressing.
 * 
 * @author Frank Cornelis
 * 
 */
public class WSAddressingHandler implements AGIVSOAPHandler {

	private static final Log LOG = LogFactory.getLog(WSAddressingHandler.class);

	private static final String TO_ID_CONTEXT_ATTRIBUTE = WSAddressingHandler.class
			.getName() + ".toId";

	private static final String MESSAGE_ID_CONTEXT_ATTRIBUTE = WSAddressingHandler.class
			.getName() + ".messageId";

	private final JAXBContext jaxbContext;

	private String action;

	private String to;

	/**
	 * Default constructor.
	 */
	public WSAddressingHandler() {
		try {
			this.jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
		} catch (JAXBException e) {
			throw new ProtocolException(e);
		}
	}

	public boolean handleMessage(SOAPMessageContext context) {
		Boolean outboundProperty = (Boolean) context
				.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		if (true == outboundProperty.booleanValue()) {
			try {
				handleOutboundMessage(context);
			} catch (SOAPException e) {
				throw new ProtocolException(e);
			}
		} else {
			handleInboundMessage(context);
		}
		return true;
	}

	private void handleInboundMessage(SOAPMessageContext context) {
		String messageId = (String) context.get(MESSAGE_ID_CONTEXT_ATTRIBUTE);
		LOG.debug("checking RelatesTo message id: " + messageId);
		Object[] headers = context.getHeaders(new QName(
				WSConstants.WS_ADDR_NAMESPACE, "RelatesTo"), this.jaxbContext,
				false);
		for (Object headerObject : headers) {
			JAXBElement<RelatesToType> element = (JAXBElement<RelatesToType>) headerObject;
			RelatesToType relatesTo = element.getValue();
			if (false == messageId.equals(relatesTo.getValue())) {
				throw new ProtocolException("incorrect a:RelatesTo value");
			}
		}
	}

	private void handleOutboundMessage(SOAPMessageContext context)
			throws SOAPException {
		LOG.debug("adding WS-Addressing headers");
		SOAPEnvelope envelope = context.getMessage().getSOAPPart()
				.getEnvelope();
		SOAPHeader header = envelope.getHeader();
		if (null == header) {
			header = envelope.addHeader();
		}

		String wsuPrefix = null;
		String wsAddrPrefix = null;
		Iterator namespacePrefixesIter = envelope.getNamespacePrefixes();
		while (namespacePrefixesIter.hasNext()) {
			String namespacePrefix = (String) namespacePrefixesIter.next();
			String namespace = envelope.getNamespaceURI(namespacePrefix);
			if (WSConstants.WS_ADDR_NAMESPACE.equals(namespace)) {
				wsAddrPrefix = namespacePrefix;
			} else if (WSConstants.WS_SECURITY_UTILITY_NAMESPACE
					.equals(namespace)) {
				wsuPrefix = namespacePrefix;
			}
		}
		if (null == wsAddrPrefix) {
			wsAddrPrefix = getUniquePrefix("a", envelope);
			envelope.addNamespaceDeclaration(wsAddrPrefix,
					WSConstants.WS_ADDR_NAMESPACE);
		}
		if (null == wsuPrefix) {
			/*
			 * Using "wsu" is very important for the IP-STS X509 credential.
			 * Apparently the STS refuses when the namespace prefix of the
			 * wsu:Id on the WS-Addressing To element is different from the
			 * wsu:Id prefix on the WS-Security timestamp.
			 */
			wsuPrefix = "wsu";
			envelope.addNamespaceDeclaration(wsuPrefix,
					WSConstants.WS_SECURITY_UTILITY_NAMESPACE);
		}

		SOAPFactory factory = SOAPFactory.newInstance();

		SOAPHeaderElement actionHeaderElement = header
				.addHeaderElement(new QName(WSConstants.WS_ADDR_NAMESPACE,
						"Action", wsAddrPrefix));
		actionHeaderElement.setMustUnderstand(true);
		actionHeaderElement.addTextNode(this.action);

		SOAPHeaderElement messageIdElement = header.addHeaderElement(new QName(
				WSConstants.WS_ADDR_NAMESPACE, "MessageID", wsAddrPrefix));
		String messageId = "urn:uuid:" + UUID.randomUUID().toString();
		context.put(MESSAGE_ID_CONTEXT_ATTRIBUTE, messageId);
		messageIdElement.addTextNode(messageId);

		SOAPHeaderElement replyToElement = header.addHeaderElement(new QName(
				WSConstants.WS_ADDR_NAMESPACE, "ReplyTo", wsAddrPrefix));
		SOAPElement addressElement = factory.createElement("Address",
				wsAddrPrefix, WSConstants.WS_ADDR_NAMESPACE);
		addressElement
				.addTextNode("http://www.w3.org/2005/08/addressing/anonymous");
		replyToElement.addChildElement(addressElement);

		SOAPHeaderElement toElement = header.addHeaderElement(new QName(
				WSConstants.WS_ADDR_NAMESPACE, "To", wsAddrPrefix));
		toElement.setMustUnderstand(true);

		toElement.addTextNode(this.to);

		String toIdentifier = "to-id-" + UUID.randomUUID().toString();
		toElement.addAttribute(new QName(
				WSConstants.WS_SECURITY_UTILITY_NAMESPACE, "Id", wsuPrefix),
				toIdentifier);
		try {
			toElement.setIdAttributeNS(
					WSConstants.WS_SECURITY_UTILITY_NAMESPACE, "Id", true);
		} catch (UnsupportedOperationException e) {
			// Axis2 has missing implementation of setIdAttributeNS
			LOG.error("error setting Id attribute: " + e.getMessage());
		}
		context.put(TO_ID_CONTEXT_ATTRIBUTE, toIdentifier);
	}

	private String getUniquePrefix(String preferredPrefix, SOAPEnvelope envelope) {
		int suffixNr = 0;
		boolean conflict;
		String prefix = preferredPrefix;
		do {
			conflict = false;
			Iterator namespacePrefixesIter = envelope.getNamespacePrefixes();
			while (namespacePrefixesIter.hasNext()) {
				String existingPrefix = (String) namespacePrefixesIter.next();
				if (prefix.equals(existingPrefix)) {
					conflict = true;
					break;
				}
			}
			if (conflict) {
				suffixNr++;
				prefix = preferredPrefix + suffixNr;
			}
		} while (conflict);
		return prefix;
	}

	public boolean handleFault(SOAPMessageContext context) {
		return true;
	}

	public void close(MessageContext context) {

	}

	public Set<QName> getHeaders() {
		Set<QName> headers = new HashSet<QName>();
		headers.add(new QName(WSConstants.WS_ADDR_NAMESPACE, "Action"));
		headers.add(new QName(WSConstants.WS_ADDR_NAMESPACE, "To"));
		return headers;
	}

	/**
	 * Sets the WS-Addressing parameters.
	 * 
	 * @param action
	 *            the WS-Addressing Action element value.
	 * @param to
	 *            the WS-Addressing To element value
	 */
	public void setAddressing(String action, String to) {
		this.action = action;
		this.to = to;
	}

	/**
	 * Gives back the u:Id attribute value of the WS-Addressing To element.
	 * 
	 * @param context
	 *            the JAX-WS SOAP message context.
	 * @return the Id attribute value of the To element.
	 */
	public static String getToIdentifier(SOAPMessageContext context) {
		return (String) context.get(TO_ID_CONTEXT_ATTRIBUTE);
	}
}
