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

package be.agiv.security.handler;

/**
 * Security Token Consumer interface. Allows for detection of the exact security
 * token provider that is used by this security token consumer.
 * 
 * @author Frank Cornelis
 * 
 */
public interface SecurityTokenConsumer {

	/**
	 * Gives back the security token provider used by this security token
	 * consumer.
	 * 
	 * @return the security token provider.
	 */
	SecurityTokenProvider getSecurityTokenProvider();
}
