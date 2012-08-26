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

package be.agiv.security.client;

import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;
import javax.xml.ws.spi.Provider;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.conversation.ConversationException;
import org.apache.ws.security.conversation.dkalgo.P_SHA1;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import be.agiv.security.SecurityToken;
import be.agiv.security.handler.LoggingHandler;
import be.agiv.security.handler.WSAddressingHandler;
import be.agiv.security.handler.WSSecurityHandler;
import be.agiv.security.handler.WSTrustHandler;
import be.agiv.security.jaxb.wsaddr.AttributedURIType;
import be.agiv.security.jaxb.wsaddr.EndpointReferenceType;
import be.agiv.security.jaxb.wspolicy.AppliesTo;
import be.agiv.security.jaxb.wsse.KeyIdentifierType;
import be.agiv.security.jaxb.wsse.SecurityTokenReferenceType;
import be.agiv.security.jaxb.wstrust.BinarySecretType;
import be.agiv.security.jaxb.wstrust.CancelTargetType;
import be.agiv.security.jaxb.wstrust.EntropyType;
import be.agiv.security.jaxb.wstrust.LifetimeType;
import be.agiv.security.jaxb.wstrust.ObjectFactory;
import be.agiv.security.jaxb.wstrust.RequestSecurityTokenResponseCollectionType;
import be.agiv.security.jaxb.wstrust.RequestSecurityTokenResponseType;
import be.agiv.security.jaxb.wstrust.RequestSecurityTokenType;
import be.agiv.security.jaxb.wstrust.RequestedReferenceType;
import be.agiv.security.jaxws.wstrust.SecurityTokenService;
import be.agiv.security.jaxws.wstrust.SecurityTokenService_Service;

/**
 * JAX-WS based AGIV IP-STS WS-Trust client. Via this client one can retrieve
 * security tokens from the IP-STS WS-Trust web service using username/password
 * or X509 certificate credentials.
 * <p/>
 * Keep in mind that this IP-STS client is specifically designed to work with
 * the AGIV IP-STS and thus will most likely not work for other IP-STS
 * configurations.
 * 
 * @author Frank Cornelis
 * 
 */
public class IPSTSClient {

	private static final Log LOG = LogFactory.getLog(IPSTSClient.class);

	private final SecurityTokenService port;

	private final ObjectFactory objectFactory;

	private final be.agiv.security.jaxb.wspolicy.ObjectFactory policyObjectFactory;

	private final be.agiv.security.jaxb.wsaddr.ObjectFactory addrObjectFactory;

	private final SecureRandom secureRandom;

	private final String location;

	private final be.agiv.security.jaxb.wsse.ObjectFactory wssObjectFactory;

	private final WSAddressingHandler wsAddressingHandler;

	private final WSTrustHandler wsTrustHandler;

	private final WSSecurityHandler wsSecurityHandler;

	private final String realm;

	/**
	 * Convenience constructor.
	 * 
	 * @param location
	 *            the location of the IP-STS WS-Trust web service.
	 * @param realm
	 *            the AGIV R-STS realm.
	 */
	public IPSTSClient(String location, String realm) {
		this(location, realm, null);
	}

	/**
	 * Main constructor.
	 * 
	 * @param location
	 *            the location of the IP-STS WS-Trust web service.
	 * @param realm
	 *            the AGIV R-STS realm.
	 * @param secondaryParametersNodeList
	 *            the DOM node list that will be used as SecondaryParameters for
	 *            RST requests.
	 */
	public IPSTSClient(String location, String realm,
			NodeList secondaryParametersNodeList) {
		this.location = location;
		this.realm = realm;

		Provider jaxwsProvider = Provider.provider();
		LOG.debug("JAX-WS provider: " + jaxwsProvider.getClass().getName());

		SecurityTokenService_Service service = SecurityTokenServiceFactory
				.getInstance();
		this.port = service.getSecurityTokenServicePort();
		BindingProvider bindingProvider = (BindingProvider) this.port;
		bindingProvider.getRequestContext().put(
				BindingProvider.ENDPOINT_ADDRESS_PROPERTY, location);

		Binding binding = bindingProvider.getBinding();
		List<Handler> handlerChain = binding.getHandlerChain();
		this.wsTrustHandler = new WSTrustHandler();
		this.wsTrustHandler.setSecondaryParameters(secondaryParametersNodeList);
		handlerChain.add(this.wsTrustHandler);
		this.wsAddressingHandler = new WSAddressingHandler();
		handlerChain.add(this.wsAddressingHandler);
		this.wsSecurityHandler = new WSSecurityHandler();
		handlerChain.add(this.wsSecurityHandler);
		handlerChain.add(new LoggingHandler());
		binding.setHandlerChain(handlerChain);

		this.objectFactory = new ObjectFactory();
		this.policyObjectFactory = new be.agiv.security.jaxb.wspolicy.ObjectFactory();
		this.addrObjectFactory = new be.agiv.security.jaxb.wsaddr.ObjectFactory();
		this.wssObjectFactory = new be.agiv.security.jaxb.wsse.ObjectFactory();

		this.secureRandom = new SecureRandom();
		this.secureRandom.setSeed(System.currentTimeMillis());
	}

	/**
	 * Retrieve a new security token from the IP-STS WS-Trust web service using
	 * the given X509 certificate credentials.
	 * 
	 * @param certificate
	 * @param privateKey
	 * @return
	 * @see IPSTSClient#getSecurityToken(String, String)
	 */
	public SecurityToken getSecuritytoken(X509Certificate certificate,
			PrivateKey privateKey) {
		SecurityToken securityToken = getSecurityToken(null, null, certificate,
				privateKey);
		return securityToken;
	}

	/**
	 * Retrieve a new security token from the IP-STS WS-Trust web service using
	 * the given username/password credentials.
	 * 
	 * @param username
	 * @param password
	 * @return the IP-STS security token to be used by the R-STS.
	 * @see IPSTSClient#getSecuritytoken(X509Certificate, PrivateKey)
	 */
	public SecurityToken getSecurityToken(String username, String password) {
		SecurityToken securityToken = getSecurityToken(username, password,
				null, null);
		return securityToken;
	}

	private SecurityToken getSecurityToken(String username, String password,
			X509Certificate certificate, PrivateKey privateKey) {
		RequestSecurityTokenType requestSecurityToken = this.objectFactory
				.createRequestSecurityTokenType();
		List<Object> requestSecurityTokenContent = requestSecurityToken
				.getAny();
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

		requestSecurityTokenContent.add(this.objectFactory
				.createKeyType(WSConstants.KEY_TYPE_SYMMETRIC));

		requestSecurityTokenContent.add(this.objectFactory.createKeySize(256L));

		if (null == this.wsTrustHandler.getSecondaryParameters()) {
			requestSecurityTokenContent
					.add(this.objectFactory
							.createKeyWrapAlgorithm(WSConstants.KEY_WRAP_ALGO_RSA_OAEP_MGF1P));

			requestSecurityTokenContent.add(this.objectFactory
					.createEncryptWith(WSConstants.ENC_ALGO_AES256_CBC));

			requestSecurityTokenContent.add(this.objectFactory
					.createSignWith(WSConstants.SIGN_ALGO_HMAC_SHA1));

			requestSecurityTokenContent
					.add(this.objectFactory
							.createCanonicalizationAlgorithm(WSConstants.C14N_ALGO_EXC));

			requestSecurityTokenContent
					.add(this.objectFactory
							.createEncryptionAlgorithm(WSConstants.ENC_ALGO_AES256_CBC));
		}

		AppliesTo appliesTo = this.policyObjectFactory.createAppliesTo();
		EndpointReferenceType endpointReference = this.addrObjectFactory
				.createEndpointReferenceType();
		AttributedURIType address = this.addrObjectFactory
				.createAttributedURIType();
		address.setValue(this.realm);
		endpointReference.setAddress(address);
		appliesTo.getAny().add(
				this.addrObjectFactory
						.createEndpointReference(endpointReference));
		requestSecurityTokenContent.add(appliesTo);

		requestSecurityTokenContent.add(this.objectFactory
				.createComputedKeyAlgorithm(WSConstants.COMP_KEY_ALGO_PSHA1));

		byte[] entropyData = new byte[256 / 8];
		// entropy = keysize / 8
		this.secureRandom.setSeed(System.currentTimeMillis());
		this.secureRandom.nextBytes(entropyData);
		binarySecret.setValue(entropyData);

		BindingProvider bindingProvider = (BindingProvider) this.port;
		if (null != username) {
			this.wsSecurityHandler.setCredentials(username, password);
		} else if (null != certificate) {
			this.wsSecurityHandler.setCredentials(privateKey, certificate);
		}
		this.wsAddressingHandler.setAddressing(
				WSConstants.WS_TRUST_ISSUE_ACTION, this.location);

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
				LOG.debug("qname: " + qname);
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
							if (securityTokenReferenceElement.getName().equals(
									WSConstants.KEY_IDENTIFIER_QNAME)) {
								KeyIdentifierType keyIdentifier = (KeyIdentifierType) securityTokenReferenceElement
										.getValue();
								String attachedReference = keyIdentifier
										.getValue();
								securityToken
										.setAttachedReference(attachedReference);
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
							if (securityTokenReferenceElement.getName().equals(
									WSConstants.KEY_IDENTIFIER_QNAME)) {
								KeyIdentifierType keyIdentifier = (KeyIdentifierType) securityTokenReferenceElement
										.getValue();
								String unattachedReference = keyIdentifier
										.getValue();
								securityToken
										.setUnattachedReference(unattachedReference);
							}

						}
					}
				}
			}
		}

		Element requestedSecurityToken = this.wsTrustHandler
				.getRequestedSecurityToken();
		securityToken.setToken(requestedSecurityToken);
		securityToken.setRealm(this.realm);
		securityToken.setStsLocation(this.location);

		return securityToken;
	}

	/**
	 * NOT FUNCTIONAL.
	 * 
	 * @param securityToken
	 */
	public void cancelSecurityToken(SecurityToken securityToken) {
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
		KeyIdentifierType keyIdentifier = this.wssObjectFactory
				.createKeyIdentifierType();
		securityTokenReference.getAny().add(
				this.wssObjectFactory.createKeyIdentifier(keyIdentifier));
		keyIdentifier.setValue(securityToken.getUnattachedReference());
		keyIdentifier.setValueType(WSConstants.SAML_KEY_IDENTIFIER_TYPE);

		BindingProvider bindingProvider = (BindingProvider) this.port;
		this.wsAddressingHandler.setAddressing(
				WSConstants.WS_TRUST_CANCEL_ACTION, this.location);
		this.wsSecurityHandler.setCredentials((String) null, (String) null);
		this.wsSecurityHandler.setKey(securityToken.getKey(),
				securityToken.getAttachedReference(), securityToken.getToken());

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
