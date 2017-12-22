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

import java.util.List;

import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.w3c.dom.Element;

import be.vlaanderen.informatievlaanderen.security.SecurityToken;
import be.vlaanderen.informatievlaanderen.security.handler.LoggingHandler;
import be.vlaanderen.informatievlaanderen.security.handler.WSAddressingHandler;
import be.vlaanderen.informatievlaanderen.security.handler.WSSecurityHandler;
import be.vlaanderen.informatievlaanderen.security.handler.WSTrustHandler;
import be.vlaanderen.informatievlaanderen.security.jaxb.wsaddr.AttributedURIType;
import be.vlaanderen.informatievlaanderen.security.jaxb.wsaddr.EndpointReferenceType;
import be.vlaanderen.informatievlaanderen.security.jaxb.wspolicy.AppliesTo;
import be.vlaanderen.informatievlaanderen.security.jaxb.wsse.KeyIdentifierType;
import be.vlaanderen.informatievlaanderen.security.jaxb.wsse.SecurityTokenReferenceType;
import be.vlaanderen.informatievlaanderen.security.jaxb.wstrust.BinarySecretType;
import be.vlaanderen.informatievlaanderen.security.jaxb.wstrust.LifetimeType;
import be.vlaanderen.informatievlaanderen.security.jaxb.wstrust.ObjectFactory;
import be.vlaanderen.informatievlaanderen.security.jaxb.wstrust.RequestSecurityTokenResponseCollectionType;
import be.vlaanderen.informatievlaanderen.security.jaxb.wstrust.RequestSecurityTokenResponseType;
import be.vlaanderen.informatievlaanderen.security.jaxb.wstrust.RequestSecurityTokenType;
import be.vlaanderen.informatievlaanderen.security.jaxb.wstrust.RequestedProofTokenType;
import be.vlaanderen.informatievlaanderen.security.jaxb.wstrust.RequestedReferenceType;
import be.vlaanderen.informatievlaanderen.security.jaxws.wstrust.SecurityTokenService;
import be.vlaanderen.informatievlaanderen.security.jaxws.wstrust.SecurityTokenService_Service;

/**
 * JAX-WS based Informatie Vlaanderen R-STS WS-Trust client. Via this client one can retrieve
 * security tokens from the R-STS WS-Trust web service using an IP-STS security
 * token.
 * <p>
 * Keep in mind that this R-STS client is specifically designed to work with the
 * Informatie Vlaanderen R-STS and thus will most likely not work for other R-STS configurations.
 * 
 * @author Frank Cornelis
 * 
 */
public class RSTSClient {

	private static final Log LOG = LogFactory.getLog(RSTSClient.class);

	private final String location;

	private final SecurityTokenService port;

	private final ObjectFactory objectFactory;

	private final be.vlaanderen.informatievlaanderen.security.jaxb.wspolicy.ObjectFactory policyObjectFactory;

	private final be.vlaanderen.informatievlaanderen.security.jaxb.wsaddr.ObjectFactory addrObjectFactory;

	private final WSAddressingHandler wsAddressingHandler;

	private final WSTrustHandler wsTrustHandler;

	private final WSSecurityHandler wsSecurityHandler;

	/**
	 * Main constructor.
	 * 
	 * @param location
	 *            the location of the R-STS WS-Trust web service.
	 */
	public RSTSClient(String location) {
		this.location = location;
		SecurityTokenService_Service service = SecurityTokenServiceFactory
				.getInstance();
		this.port = service.getSecurityTokenServicePort();
		BindingProvider bindingProvider = (BindingProvider) this.port;
		bindingProvider.getRequestContext().put(
				BindingProvider.ENDPOINT_ADDRESS_PROPERTY, location);

		Binding binding = bindingProvider.getBinding();
		List<Handler> handlerChain = binding.getHandlerChain();
		this.wsTrustHandler = new WSTrustHandler();
		handlerChain.add(this.wsTrustHandler);
		this.wsAddressingHandler = new WSAddressingHandler();
		handlerChain.add(this.wsAddressingHandler);
		this.wsSecurityHandler = new WSSecurityHandler();
		handlerChain.add(this.wsSecurityHandler);
		handlerChain.add(new LoggingHandler());
		binding.setHandlerChain(handlerChain);

		this.objectFactory = new ObjectFactory();
		this.policyObjectFactory = new be.vlaanderen.informatievlaanderen.security.jaxb.wspolicy.ObjectFactory();
		this.addrObjectFactory = new be.vlaanderen.informatievlaanderen.security.jaxb.wsaddr.ObjectFactory();

	}

	/**
	 * Retrieves a new security token from the R-STS WS-Trust web service using
	 * the given IP-STS security token. The security token retrieved from the
	 * R-STS always applies to a certain Informatie Vlaanderen web service. The location of this
	 * Informatie Vlaanderen web service is also passed as parameter.
	 * 
	 * @param ipStsSecurityToken
	 *            the IP-STS security token.
	 * @param appliesTo
	 *            the WS-SecureConversation enabled web service to which the
	 *            R-STS security token should apply.
	 * @return the R-STS security token to be used by the service Secure
	 *         Conversation.
	 */
	public SecurityToken getSecurityToken(SecurityToken ipStsSecurityToken,
			String appliesTo) {
		RequestSecurityTokenType requestSecurityToken = this.objectFactory
				.createRequestSecurityTokenType();
		List<Object> requestSecurityTokenContent = requestSecurityToken
				.getAny();
		requestSecurityTokenContent.add(this.objectFactory
				.createRequestType(WSConstants.ISSUE_REQUEST_TYPE));

		AppliesTo jaxbAppliesTo = this.policyObjectFactory.createAppliesTo();
		EndpointReferenceType endpointReference = this.addrObjectFactory
				.createEndpointReferenceType();
		AttributedURIType address = this.addrObjectFactory
				.createAttributedURIType();
		address.setValue(appliesTo);
		endpointReference.setAddress(address);
		jaxbAppliesTo.getAny().add(
				this.addrObjectFactory
						.createEndpointReference(endpointReference));
		requestSecurityTokenContent.add(jaxbAppliesTo);

		BindingProvider bindingProvider = (BindingProvider) this.port;
		this.wsAddressingHandler.setAddressing(
				WSConstants.WS_TRUST_ISSUE_ACTION, this.location);
		this.wsSecurityHandler.setKey(ipStsSecurityToken.getKey(),
				ipStsSecurityToken.getAttachedReference(),
				ipStsSecurityToken.getToken());

		RequestSecurityTokenResponseCollectionType requestSecurityTokenResponseCollection = this.port
				.requestSecurityToken(requestSecurityToken);

		SecurityToken securityToken = new SecurityToken();

		List<RequestSecurityTokenResponseType> requestSecurityTokenResponseList = requestSecurityTokenResponseCollection
				.getRequestSecurityTokenResponse();
		RequestSecurityTokenResponseType requestSecurityTokenResponse = requestSecurityTokenResponseList
				.get(0);
		List<Object> requestSecurityTokenResponseContent = requestSecurityTokenResponse
				.getAny();
		for (Object contentObject : requestSecurityTokenResponseContent) {
			LOG.debug("content object: " + contentObject.getClass().getName());
			if (contentObject instanceof Element) {
				Element contentElement = (Element) contentObject;
				LOG.debug("element name: " + contentElement.getLocalName());
			}
			if (contentObject instanceof JAXBElement) {
				JAXBElement jaxbElement = (JAXBElement) contentObject;
				QName qname = jaxbElement.getName();
				LOG.debug("JAXB qname: " + qname);
				if (WSConstants.LIFETIME_QNAME.equals(qname)) {
					LOG.debug("trust:Lifetime");
					LifetimeType lifetime = (LifetimeType) jaxbElement
							.getValue();
					String createdValue = lifetime.getCreated().getValue();
					DateTimeFormatter dateTimeFormatter = ISODateTimeFormat
							.dateTimeParser();
					DateTime created = dateTimeFormatter
							.parseDateTime(createdValue);
					securityToken.setCreated(created.toDate());
					String expiresString = lifetime.getExpires().getValue();
					DateTime expires = dateTimeFormatter
							.parseDateTime(expiresString);
					securityToken.setExpires(expires.toDate());
				} else if (WSConstants.REQUESTED_ATTACHED_REFERENCE_QNAME
						.equals(qname)) {
					RequestedReferenceType requestedReference = (RequestedReferenceType) jaxbElement
							.getValue();
					SecurityTokenReferenceType securityTokenReference = requestedReference
							.getSecurityTokenReference();
					List<Object> securityTokenReferenceContent = securityTokenReference
							.getAny();
					for (Object securityTokenReferenceObject : securityTokenReferenceContent) {
						LOG.debug("SecurityTokenReference object: "
								+ securityTokenReferenceObject.getClass()
										.getName());
						if (securityTokenReferenceObject instanceof JAXBElement) {
							JAXBElement securityTokenReferenceElement = (JAXBElement) securityTokenReferenceObject;
							LOG.debug("SecurityTokenReference element: "
									+ securityTokenReferenceElement.getName());
							if (securityTokenReferenceElement.getName().equals(
									WSConstants.KEY_IDENTIFIER_QNAME)) {
								KeyIdentifierType keyIdentifier = (KeyIdentifierType) securityTokenReferenceElement
										.getValue();
								String tokenIdentifier = keyIdentifier
										.getValue();
								securityToken
										.setAttachedReference(tokenIdentifier);
							}
						}
					}
				} else if (WSConstants.REQUESTED_PROOF_TOKEN_QNAME
						.equals(qname)) {
					RequestedProofTokenType requestedProofToken = (RequestedProofTokenType) jaxbElement
							.getValue();
					Object requestedProofTokenContent = requestedProofToken
							.getAny();
					LOG.debug("requested proof token content: "
							+ requestedProofTokenContent.getClass().getName());
					if (requestedProofTokenContent instanceof JAXBElement) {
						JAXBElement requestedProofTokenElement = (JAXBElement) requestedProofTokenContent;
						LOG.debug("requested proof token element: "
								+ requestedProofTokenElement.getName());
						if (WSConstants.BINARY_SECRET_QNAME
								.equals(requestedProofTokenElement.getName())) {
							BinarySecretType serverBinarySecret = (BinarySecretType) requestedProofTokenElement
									.getValue();
							byte[] serverSecret = serverBinarySecret.getValue();
							securityToken.setKey(serverSecret);
						}
					}
				}
			}
		}

		Element requestedSecurityToken = this.wsTrustHandler
				.getRequestedSecurityToken();
		securityToken.setToken(requestedSecurityToken);
		securityToken.setRealm(appliesTo);
		securityToken.setStsLocation(this.location);
		securityToken.setParentSecurityToken(ipStsSecurityToken);

		return securityToken;
	}
}
