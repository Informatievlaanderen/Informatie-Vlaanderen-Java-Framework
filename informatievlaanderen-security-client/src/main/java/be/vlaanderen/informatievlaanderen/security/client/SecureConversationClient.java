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

import java.security.SecureRandom;
import java.util.List;

import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.conversation.ConversationException;
import org.apache.ws.security.conversation.dkalgo.P_SHA1;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.w3c.dom.Element;

import be.vlaanderen.informatievlaanderen.security.SecurityToken;
import be.vlaanderen.informatievlaanderen.security.handler.LoggingHandler;
import be.vlaanderen.informatievlaanderen.security.handler.WSAddressingHandler;
import be.vlaanderen.informatievlaanderen.security.handler.WSSecurityHandler;
import be.vlaanderen.informatievlaanderen.security.handler.WSTrustHandler;
import be.vlaanderen.informatievlaanderen.security.jaxb.wsse.ReferenceType;
import be.vlaanderen.informatievlaanderen.security.jaxb.wsse.SecurityTokenReferenceType;
import be.vlaanderen.informatievlaanderen.security.jaxb.wstrust.BinarySecretType;
import be.vlaanderen.informatievlaanderen.security.jaxb.wstrust.CancelTargetType;
import be.vlaanderen.informatievlaanderen.security.jaxb.wstrust.EntropyType;
import be.vlaanderen.informatievlaanderen.security.jaxb.wstrust.LifetimeType;
import be.vlaanderen.informatievlaanderen.security.jaxb.wstrust.ObjectFactory;
import be.vlaanderen.informatievlaanderen.security.jaxb.wstrust.RequestSecurityTokenResponseCollectionType;
import be.vlaanderen.informatievlaanderen.security.jaxb.wstrust.RequestSecurityTokenResponseType;
import be.vlaanderen.informatievlaanderen.security.jaxb.wstrust.RequestSecurityTokenType;
import be.vlaanderen.informatievlaanderen.security.jaxb.wstrust.RequestedReferenceType;
import be.vlaanderen.informatievlaanderen.security.jaxws.wstrust.SecurityTokenService;
import be.vlaanderen.informatievlaanderen.security.jaxws.wstrust.SecurityTokenService_Service;

/**
 * JAX-WS based WS-SecureConversation client. Via this client one can setup
 * secure conversations according to the WS-SecureConversation specification. A
 * conversation is presented via a secure conversation token.
 * 
 * @author Frank Cornelis
 * 
 */
public class SecureConversationClient {

	private static final Log LOG = LogFactory
			.getLog(SecureConversationClient.class);

	private final String location;

	private final SecurityTokenService port;

	private final ObjectFactory objectFactory;

	private final SecureRandom secureRandom;

	private final be.vlaanderen.informatievlaanderen.security.jaxb.wsse.ObjectFactory wssObjectFactory;

	private final WSAddressingHandler wsAddressingHandler;

	private final WSTrustHandler wsTrustHandler;

	private final WSSecurityHandler wsSecurityHandler;

	/**
	 * Main constructor. The given location is the same as where the actual
	 * business web service is running.
	 * 
	 * @param location
	 *            the location of the WS-SecureConversation enabled web service.
	 */
	public SecureConversationClient(String location) {
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
		this.wssObjectFactory = new be.vlaanderen.informatievlaanderen.security.jaxb.wsse.ObjectFactory();

		this.secureRandom = new SecureRandom();
		this.secureRandom.setSeed(System.currentTimeMillis());
	}

	/**
	 * Gives back a secure conversation token using the given R-STS security
	 * token. The R-STS security token should apply to this web service.
	 * 
	 * @param rStsSecurityToken
	 *            the R-STS security token.
	 * @return the secure conversation token to be used to secure the web
	 *         service calls.
	 */
	public SecurityToken getSecureConversationToken(
			SecurityToken rStsSecurityToken) {
		RequestSecurityTokenType requestSecurityToken = this.objectFactory
				.createRequestSecurityTokenType();
		List<Object> requestSecurityTokenContent = requestSecurityToken
				.getAny();

		requestSecurityTokenContent.add(this.objectFactory
				.createTokenType(WSConstants.SECURE_CONVERSATION_TOKEN_TYPE));

		requestSecurityTokenContent.add(this.objectFactory
				.createRequestType(WSConstants.ISSUE_REQUEST_TYPE));

		EntropyType entropy = this.objectFactory.createEntropyType();
		requestSecurityTokenContent.add(this.objectFactory
				.createEntropy(entropy));
		BinarySecretType binarySecret = this.objectFactory
				.createBinarySecretType();
		entropy.getAny().add(
				this.objectFactory.createBinarySecret(binarySecret));
		binarySecret.setType(WSConstants.SECRET_TYPE_NONCE);
		byte[] entropyData = new byte[256 / 8];
		this.secureRandom.setSeed(System.currentTimeMillis());
		this.secureRandom.nextBytes(entropyData);
		binarySecret.setValue(entropyData);

		requestSecurityTokenContent.add(this.objectFactory.createKeySize(256L));

		BindingProvider bindingProvider = (BindingProvider) this.port;
		this.wsAddressingHandler.setAddressing(
				WSConstants.SEC_CONV_ISSUE_ACTION, this.location);
		this.wsSecurityHandler.setKey(rStsSecurityToken.getKey(),
				rStsSecurityToken.getAttachedReference(),
				rStsSecurityToken.getToken());

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
				if (WSConstants.ENTROPY_QNAME.equals(qname)) {
					LOG.debug("trust:Entropy");
					EntropyType serverEntropy = (EntropyType) jaxbElement
							.getValue();
					List<Object> entropyContent = serverEntropy.getAny();
					for (Object entropyObject : entropyContent) {
						if (entropyObject instanceof JAXBElement) {
							JAXBElement entropyElement = (JAXBElement) entropyObject;
							if (WSConstants.BINARY_SECRET_QNAME
									.equals(entropyElement.getName())) {
								BinarySecretType serverBinarySecret = (BinarySecretType) entropyElement
										.getValue();
								byte[] serverSecret = serverBinarySecret
										.getValue();
								P_SHA1 p_SHA1 = new P_SHA1();
								byte[] key;
								try {
									key = p_SHA1.createKey(entropyData,
											serverSecret, 0, 256 / 8);
								} catch (ConversationException e) {
									LOG.error(e);
									return null;
								}
								LOG.debug("client secret size: "
										+ entropyData.length);
								LOG.debug("server secret size: "
										+ serverSecret.length);
								LOG.debug("key size: " + key.length);
								securityToken.setKey(key);
							}
						}
					}
				} else if (WSConstants.LIFETIME_QNAME.equals(qname)) {
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
							if (WSConstants.REFERENCE_QNAME
									.equals(securityTokenReferenceElement
											.getName())) {
								ReferenceType reference = (ReferenceType) securityTokenReferenceElement
										.getValue();
								String tokenIdentifier = reference.getURI()
										.substring(1);
								securityToken
										.setAttachedReference(tokenIdentifier);
							}
						}
					}
				} else if (WSConstants.REQUESTED_UNATTACHED_REFERENCE_QNAME
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
							if (WSConstants.REFERENCE_QNAME
									.equals(securityTokenReferenceElement
											.getName())) {
								ReferenceType reference = (ReferenceType) securityTokenReferenceElement
										.getValue();
								String tokenIdentifier = reference.getURI();
								securityToken
										.setUnattachedReference(tokenIdentifier);
							}
						}
					}
				}
			}
		}

		Element requestedSecurityToken = this.wsTrustHandler
				.getRequestedSecurityToken();
		securityToken.setToken(requestedSecurityToken);
		securityToken.setStsLocation(this.location);
		securityToken.setRealm(this.location); // what else?
		securityToken.setParentSecurityToken(rStsSecurityToken);

		return securityToken;
	}

	/**
	 * Cancels a given secure conversation token for this WS-SecureConversation
	 * enabled web service.
	 * 
	 * @param secureConversationToken
	 */
	public void cancelSecureConversationToken(
			SecurityToken secureConversationToken) {
		RequestSecurityTokenType requestSecurityToken = this.objectFactory
				.createRequestSecurityTokenType();
		List<Object> requestSecurityTokenContent = requestSecurityToken
				.getAny();

		requestSecurityTokenContent.add(this.objectFactory
				.createRequestType(WSConstants.CANCEL_REQUEST_TYPE));

		CancelTargetType cancelTarget = this.objectFactory
				.createCancelTargetType();
		requestSecurityTokenContent.add(this.objectFactory
				.createCancelTarget(cancelTarget));
		SecurityTokenReferenceType securityTokenReference = this.wssObjectFactory
				.createSecurityTokenReferenceType();
		cancelTarget.setAny(this.wssObjectFactory
				.createSecurityTokenReference(securityTokenReference));
		ReferenceType reference = this.wssObjectFactory.createReferenceType();
		securityTokenReference.getAny().add(
				this.wssObjectFactory.createReference(reference));
		reference.setURI(secureConversationToken.getUnattachedReference());
		reference.setValueType(WSConstants.SECURE_CONVERSATION_TOKEN_TYPE);

		BindingProvider bindingProvider = (BindingProvider) this.port;
		this.wsAddressingHandler.setAddressing(
				WSConstants.SEC_CONV_CANCEL_ACTION, this.location);
		this.wsSecurityHandler.setKey(secureConversationToken.getKey(),
				secureConversationToken.getAttachedReference(),
				secureConversationToken.getToken(), false);

		RequestSecurityTokenResponseCollectionType requestSecurityTokenResponseCollection = this.port
				.requestSecurityToken(requestSecurityToken);

		List<RequestSecurityTokenResponseType> requestSecurityTokenResponseList = requestSecurityTokenResponseCollection
				.getRequestSecurityTokenResponse();
		RequestSecurityTokenResponseType requestSecurityTokenResponse = requestSecurityTokenResponseList
				.get(0);
		List<Object> requestSecurityTokenResponseContent = requestSecurityTokenResponse
				.getAny();
		boolean tokenCancelled = false;
		for (Object contentObject : requestSecurityTokenResponseContent) {
			LOG.debug("content object: " + contentObject.getClass().getName());
			if (contentObject instanceof JAXBElement) {
				JAXBElement jaxbElement = (JAXBElement) contentObject;
				QName qname = jaxbElement.getName();
				LOG.debug("qname: " + qname);
				if (WSConstants.REQUESTED_TOKEN_CANCELLED_QNAME.equals(qname)) {
					tokenCancelled = true;
				}
			}
		}
		if (false == tokenCancelled) {
			throw new RuntimeException("token not cancelled");
		}
	}
}
