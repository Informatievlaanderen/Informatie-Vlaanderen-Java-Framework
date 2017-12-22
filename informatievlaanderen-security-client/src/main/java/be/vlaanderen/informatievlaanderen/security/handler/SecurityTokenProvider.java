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

import be.vlaanderen.informatievlaanderen.security.SecurityToken;

/**
 * Interface for providers of security tokens.
 * 
 * @author Frank Cornelis
 * 
 */
public interface SecurityTokenProvider {

	/**
	 * Gives back the secure conversation token for the given web service
	 * location.
	 * 
	 * @param location
	 *            the location of the web service.
	 * @param serviceRealm
	 *            the service realm of the web service for which the token
	 *            should apply.
	 * 
	 * @return the secure conversation token
	 */
	SecurityToken getSecureConversationToken(String location,
			String serviceRealm);

	/**
	 * Gives back the R-STS security token for the given web service location.
	 * 
	 * @param serviceRealm
	 *            the service realm of the web service for which the token
	 *            should apply.
	 * @return the R-STS security token.
	 */
	SecurityToken getSecurityToken(String serviceRealm);
}
