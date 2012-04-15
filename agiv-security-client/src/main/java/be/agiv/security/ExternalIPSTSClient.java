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

/**
 * Interface for external IP-STS service clients.
 * <p/>
 * Can be used for external IP-STS services that do not behave like the AGIV
 * IP-STS.
 * 
 * @author Frank Cornelis
 * 
 */
public interface ExternalIPSTSClient {

	/**
	 * Gives back the IP-STS security token. It is up to the implementing class
	 * to decide on how to collect the required user credentials.
	 * 
	 * @return the retrieved IP-STS security token.
	 */
	SecurityToken getSecurityToken();
}
