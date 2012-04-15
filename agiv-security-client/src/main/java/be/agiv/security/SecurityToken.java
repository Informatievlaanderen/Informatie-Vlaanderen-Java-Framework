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

package be.agiv.security;

import java.util.Date;

import org.w3c.dom.Element;

/**
 * A security token holds the WS-Trust and WS-SecureConversation tokens. A
 * security token can have a corresponding key. This key can be used in the
 * different STS proof-of-possessions.
 * 
 * @author Frank Cornelis
 * 
 */
public class SecurityToken {

	private byte[] key;

	private Date created;

	private Date expires;

	private Element token;

	private String attachedReference;

	private String unattachedReference;

	/**
	 * Sets the security token proof of possession key. This is most likely a
	 * symmetric key or secret.
	 * 
	 * @param key
	 *            the key.
	 */
	public void setKey(byte[] key) {
		this.key = key;
	}

	/**
	 * Gives back the security token proof of possession key.
	 * 
	 * @return the key.
	 */
	public byte[] getKey() {
		return this.key;
	}

	/**
	 * Sets the creation date of the security token.
	 * 
	 * @param created
	 *            the creation date of the token.
	 */
	public void setCreated(Date created) {
		this.created = created;
	}

	/**
	 * Gives back the creation date of the security token.
	 * 
	 * @return the creation date of the token.
	 */
	public Date getCreated() {
		return this.created;
	}

	/**
	 * Sets the expiry date of the security token.
	 * 
	 * @param expires
	 *            the expiry date of the token.
	 */
	public void setExpires(Date expires) {
		this.expires = expires;
	}

	/**
	 * Gives back the expiry date of the security token.
	 * 
	 * @return the expiry date of the token.
	 */
	public Date getExpires() {
		return this.expires;
	}

	/**
	 * Sets the security token as DOM element.
	 * 
	 * @param requestedSecurityToken
	 *            the token as DOM element.
	 */
	public void setToken(Element requestedSecurityToken) {
		this.token = requestedSecurityToken;
	}

	/**
	 * Gives back the security token as DOM element.
	 * 
	 * @return the token as DOM element.
	 */
	public Element getToken() {
		return this.token;
	}

	/**
	 * Sets the security token identifier for attached references. Via these
	 * identifiers you can reference the security tokens in the different STS
	 * messages.
	 * 
	 * @param attachedReference
	 */
	public void setAttachedReference(String attachedReference) {
		this.attachedReference = attachedReference;
	}

	/**
	 * Gives back the security token identifier for attached references.
	 * 
	 * @return
	 */
	public String getAttachedReference() {
		return this.attachedReference;
	}

	/**
	 * Sets the security token identifier for unattached references.
	 * 
	 * @param unattachedReference
	 */
	public void setUnattachedReference(String unattachedReference) {
		this.unattachedReference = unattachedReference;
	}

	/**
	 * Gives back the security token identifier for unattached references.
	 * 
	 * @return
	 */
	public String getUnattachedReference() {
		return this.unattachedReference;
	}
}
