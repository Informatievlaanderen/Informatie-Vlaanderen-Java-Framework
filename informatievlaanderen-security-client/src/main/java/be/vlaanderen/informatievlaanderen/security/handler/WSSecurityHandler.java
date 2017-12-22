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

package be.vlaanderen.informatievlaanderen.security.handler;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Vector;

import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.ws.ProtocolException;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.conversation.ConversationException;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.message.WSSecTimestamp;
import org.apache.ws.security.message.WSSecUsernameToken;
import org.apache.ws.security.message.token.Timestamp;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignatureException;
import org.w3c.dom.Element;

/**
 * A JAX-WS based SOAP handler that implements WS-Security as required for the
 * different Informatie Vlaanderen web services.
 * 
 * @author Frank Cornelis
 * 
 */
public class WSSecurityHandler implements InformatieVlaanderenSOAPHandler {

	private static final Log LOG = LogFactory.getLog(WSSecurityHandler.class);

	private String username;

	private String password;

	private PrivateKey privateKey;

	private X509Certificate certificate;

	private byte[] key;

	private String tokenIdentifier;

	private Element token;

	private boolean samlReference;

	public boolean handleMessage(SOAPMessageContext context) {
		Boolean outboundProperty = (Boolean) context
				.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);

		if (true == outboundProperty.booleanValue()) {
			try {
				handleOutboundMessage(context);
			} catch (Exception e) {
				LOG.error("outbound exception: " + e.getMessage(), e);
				throw new ProtocolException(e);
			}
		} else {
			try {
				handleInboundMessage(context);
			} catch (Exception e) {
				throw new ProtocolException(e);
			}
		}

		return true;
	}

	private void handleInboundMessage(SOAPMessageContext context)
			throws WSSecurityException {
		LOG.debug("checking WS-Security header");
		SOAPMessage soapMessage = context.getMessage();
		SOAPPart soapPart = soapMessage.getSOAPPart();

		WSSecurityEngine secEngine = new WSSecurityEngine();
		List<WSSecurityEngineResult> results = secEngine.processSecurityHeader(
				soapPart, null, null, null);
		if (null == results) {
			throw new SecurityException("no WS-Security results");
		}

		WSSecurityEngineResult actionResult = WSSecurityUtil.fetchActionResult(
				results, WSConstants.TS);
		if (null == actionResult) {
			throw new SecurityException("no WS-Security timestamp result");
		}

		Timestamp receivedTimestamp = (Timestamp) actionResult
				.get(WSSecurityEngineResult.TAG_TIMESTAMP);
		if (null == receivedTimestamp) {
			throw new SecurityException("no WS-Security timestamp");
		}

		LOG.debug("WS-Security timestamp created: "
				+ receivedTimestamp.getCreated());
		LOG.debug("WS-Security timestamp expires: "
				+ receivedTimestamp.getExpires());
	}

	private void handleOutboundMessage(SOAPMessageContext context)
			throws WSSecurityException, ConversationException, SOAPException,
			IOException, XMLSignatureException, XMLSecurityException {
		LOG.debug("adding WS-Security header");
		SOAPMessage soapMessage = context.getMessage();
		SOAPPart soapPart = soapMessage.getSOAPPart();

		SOAPHeader soapHeader = soapMessage.getSOAPHeader();
		if (null == soapHeader) {
			/*
			 * Work-around for Axis2.
			 */
			SOAPEnvelope soapEnvelope = soapPart.getEnvelope();
			soapHeader = soapEnvelope.addHeader();
		}

		WSSecHeader wsSecHeader = new WSSecHeader();
		Element securityElement = wsSecHeader.insertSecurityHeader(soapPart);

		addToken(context, securityElement);

		addUsernamePassword(context, soapPart, wsSecHeader);

		WSSecTimestamp wsSecTimeStamp = new WSSecTimestamp();
		wsSecTimeStamp.build(soapPart, wsSecHeader);

		addProofOfPossessionSignature(context, soapMessage, soapPart,
				wsSecHeader, wsSecTimeStamp);

		addCertificateSignature(context, soapPart, wsSecHeader, wsSecTimeStamp);

		/*
		 * Really needs to be at the end for Axis2 to work. Axiom bug?
		 */
		appendSecurityHeader(soapHeader, securityElement);
	}

	private void appendSecurityHeader(SOAPHeader soapHeader,
			Element securityElement) {
		soapHeader.removeChild(securityElement);
		soapHeader.appendChild(securityElement);
	}

	private void addCertificateSignature(SOAPMessageContext context,
			SOAPPart soapPart, WSSecHeader wsSecHeader,
			WSSecTimestamp wsSecTimeStamp) throws WSSecurityException {
		if (null == this.certificate) {
			return;
		}
		String toIdentifier = WSAddressingHandler.getToIdentifier(context);
		LOG.debug("wsa:To/@wsu:Id = " + toIdentifier);
		WSSecurityCrypto crypto = new WSSecurityCrypto(this.privateKey,
				this.certificate);
		WSSConfig wssConfig = new WSSConfig();
		wssConfig.setWsiBSPCompliant(false);
		WSSecSignature sign = new WSSecSignature(wssConfig);
		sign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
		sign.prepare(soapPart, crypto, wsSecHeader);
		sign.appendBSTElementToHeader(wsSecHeader);
		Vector<WSEncryptionPart> signParts = new Vector<WSEncryptionPart>();
		signParts.add(new WSEncryptionPart(wsSecTimeStamp.getId()));
		signParts.add(new WSEncryptionPart(toIdentifier));
		sign.addReferencesToSign(signParts, wsSecHeader);
		List<Reference> referenceList = sign.addReferencesToSign(signParts,
				wsSecHeader);
		sign.computeSignature(referenceList, false, null);
	}

	private void addProofOfPossessionSignature(SOAPMessageContext context,
			SOAPMessage soapMessage, SOAPPart soapPart,
			WSSecHeader wsSecHeader, WSSecTimestamp wsSecTimeStamp)
			throws SOAPException, IOException, WSSecurityException {
		if (null == this.key) {
			return;
		}
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		soapMessage.writeTo(outputStream);
		LOG.debug("SOAP message before signing: "
				+ new String(outputStream.toByteArray()));
		Vector<WSEncryptionPart> signParts = new Vector<WSEncryptionPart>();
		signParts.add(new WSEncryptionPart(wsSecTimeStamp.getId()));

		LOG.debug("token identifier: " + this.tokenIdentifier);

		WSSConfig wssConfig = new WSSConfig();
		WSSecSignature sign = new WSSecSignature(wssConfig);
		if (this.samlReference) {
			sign.setKeyIdentifierType(WSConstants.CUSTOM_KEY_IDENTIFIER);
			sign.setCustomTokenValueType(WSConstants.WSS_SAML_KI_VALUE_TYPE);
		} else {
			sign.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
		}
		sign.setSecretKey(this.key);
		sign.setSignatureAlgorithm(SignatureMethod.HMAC_SHA1);
		sign.setCustomTokenId(this.tokenIdentifier);
		sign.prepare(soapPart, null, wsSecHeader);
		sign.setParts(signParts);
		List<Reference> referenceList = sign.addReferencesToSign(signParts,
				wsSecHeader);
		sign.computeSignature(referenceList, false, null);
	}

	private void addUsernamePassword(SOAPMessageContext context,
			SOAPPart soapPart, WSSecHeader wsSecHeader) {
		if (null == this.username) {
			return;
		}
		LOG.debug("adding Username token");
		WSSecUsernameToken usernameToken = new WSSecUsernameToken();
		usernameToken.setUserInfo(this.username, this.password);
		// WSConstants.PASSWORD_DIGEST is not supported by Informatie Vlaanderen IP-STS
		usernameToken.setPasswordType(WSConstants.PASSWORD_TEXT);
		usernameToken.prepare(soapPart);
		usernameToken.prependToHeader(wsSecHeader);
	}

	private void addToken(SOAPMessageContext context, Element securityElement) {
		if (null != this.token) {
			LOG.debug("adding WS-Security token");
			securityElement.appendChild(securityElement.getOwnerDocument()
					.importNode(this.token, true));
		}
	}

	public boolean handleFault(SOAPMessageContext context) {
		return true;
	}

	public void close(MessageContext context) {
	}

	public Set<QName> getHeaders() {
		Set<QName> headers = new HashSet<QName>();
		headers.add(new QName(
				be.vlaanderen.informatievlaanderen.security.client.WSConstants.WS_SECURITY_NAMESPACE,
				"Security"));
		return headers;
	}

	/**
	 * Sets the WS-Security username/password credentials.
	 * 
	 * @param username
	 *            the username.
	 * @param password
	 *            the corresponding password.
	 * @see WSSecurityHandler#setCredentials(PrivateKey, X509Certificate)
	 */
	public void setCredentials(String username, String password) {
		this.username = username;
		this.password = password;
	}

	/**
	 * Sets the SAML token and proof of possession key used to sign requests via
	 * WS-Security.
	 * 
	 * @param key
	 *            the proof-of-possession key.
	 * @param tokenIdentifier
	 *            the SAML token identifier.
	 * @param token
	 *            the SAML token.
	 */
	public void setKey(byte[] key, String tokenIdentifier, Element token) {
		setKey(key, tokenIdentifier, token, true);
	}

	/**
	 * Sets the token and proof of possession key used to sign requests via
	 * WS-Security.
	 * 
	 * @param key
	 *            the proof of possession key for WS-Security signing.
	 * @param tokenIdentifier
	 *            the token identifier
	 * @param token
	 *            the security or secure conversation token
	 * @param samlReference
	 *            <code>true</code> if the WS-Security signature should refer to
	 *            the token as being a SAML token.
	 */
	public void setKey(byte[] key, String tokenIdentifier, Element token,
			boolean samlReference) {
		this.key = key;
		this.tokenIdentifier = tokenIdentifier;
		this.token = token;
		this.samlReference = samlReference;
	}

	/**
	 * Sets the WS-Security X509 credentials.
	 * 
	 * @param privateKey
	 * @param certificate
	 * @see WSSecurityHandler#setCredentials(String, String)
	 */
	public void setCredentials(PrivateKey privateKey,
			X509Certificate certificate) {
		this.privateKey = privateKey;
		this.certificate = certificate;
	}
}
