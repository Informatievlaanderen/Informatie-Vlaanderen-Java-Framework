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

import javax.xml.namespace.QName;

/**
 * WS-* constants.
 * 
 * @author Frank Cornelis
 * 
 */
public class WSConstants {

	/*
	 * Namespaces
	 */
	public static final String WS_ADDR_NAMESPACE = "http://www.w3.org/2005/08/addressing";

	public static final String SEC_CONV_NAMESPACE = "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512";

	public static final String WSTRUST_NAMESPACE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";

	public static final String WS_SECURITY_NAMESPACE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

	public static final String WS_SECURITY_UTILITY_NAMESPACE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

	public static final String SOAP12_NAMESPACE = "http://www.w3.org/2003/05/soap-envelope";

	public static final String WS_SECURITY_POLICY_NAMESPACE = "http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702";

	/*
	 * WS-Trust
	 */
	public static final String ISSUE_REQUEST_TYPE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue";

	public static final String SECRET_TYPE_NONCE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Nonce";

	public static final String KEY_TYPE_SYMMETRIC = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey";

	public static final String KEY_WRAP_ALGO_RSA_OAEP_MGF1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

	public static final String ENC_ALGO_AES256_CBC = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";

	public static final String SIGN_ALGO_HMAC_SHA1 = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";

	public static final String C14N_ALGO_EXC = "http://www.w3.org/2001/10/xml-exc-c14n#";

	public static final String COMP_KEY_ALGO_PSHA1 = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/CK/PSHA1";

	public static final String WS_TRUST_CANCEL_ACTION = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Cancel";

	public static final String SAML_KEY_IDENTIFIER_TYPE = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID";

	public static final String WS_TRUST_ISSUE_ACTION = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue";

	public static final String CANCEL_REQUEST_TYPE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Cancel";

	/*
	 * WS-SecureConversation
	 */
	public static final String SECURE_CONVERSATION_TOKEN_TYPE = "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/sct";

	public static final String SEC_CONV_ISSUE_ACTION = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/SCT";

	public static final String SEC_CONV_CANCEL_ACTION = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/SCT/Cancel";

	/*
	 * WS-Trust QNames
	 */
	public static final QName ENTROPY_QNAME = new QName(WSTRUST_NAMESPACE,
			"Entropy");

	public static final QName BINARY_SECRET_QNAME = new QName(
			WSTRUST_NAMESPACE, "BinarySecret");

	public static final QName LIFETIME_QNAME = new QName(WSTRUST_NAMESPACE,
			"Lifetime");

	public static final QName REQUESTED_ATTACHED_REFERENCE_QNAME = new QName(
			WSTRUST_NAMESPACE, "RequestedAttachedReference");

	public static final QName REQUESTED_UNATTACHED_REFERENCE_QNAME = new QName(
			WSTRUST_NAMESPACE, "RequestedUnattachedReference");

	public static final QName REQUEST_SECURITY_TOKEN_RESPONSE_QNAME = new QName(
			WSTRUST_NAMESPACE, "RequestSecurityTokenResponse");

	public final static QName REQUESTED_PROOF_TOKEN_QNAME = new QName(
			WSTRUST_NAMESPACE, "RequestedProofToken");

	public static final QName REQUESTED_TOKEN_CANCELLED_QNAME = new QName(
			WSTRUST_NAMESPACE, "RequestedTokenCancelled");

	/*
	 * WS-Security QNames
	 */
	public static final QName REFERENCE_QNAME = new QName(
			WS_SECURITY_NAMESPACE, "Reference");

	public static final QName KEY_IDENTIFIER_QNAME = new QName(
			WS_SECURITY_NAMESPACE, "KeyIdentifier");

	/*
	 * WS-SecureConversation QNames
	 */
	public static final QName IDENTIFIER_QNAME = new QName(SEC_CONV_NAMESPACE,
			"Identifier");

	private WSConstants() {
		super();
	}
}
