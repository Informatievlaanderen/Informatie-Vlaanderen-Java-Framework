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

package test.integ.be.vlaanderen.informatievlaanderen.security;

import java.util.HashMap;
import java.util.Map;

import be.vlaanderen.informatievlaanderen.security.SecurityToken;
import be.vlaanderen.informatievlaanderen.security.handler.SecurityTokenProvider;

public class TestSecurityTokenProvider implements SecurityTokenProvider {

	private final Map<String, SecurityToken> securityTokens;

	public TestSecurityTokenProvider() {
		this.securityTokens = new HashMap<String, SecurityToken>();
	}

	public void addSecurityToken(String location, SecurityToken securityToken) {
		this.securityTokens.put(location, securityToken);
	}

	@Override
	public SecurityToken getSecureConversationToken(String location,
			String serviceRealm) {
		return null;
	}

	@Override
	public SecurityToken getSecurityToken(String location) {
		return this.securityTokens.get(location);
	}
}
