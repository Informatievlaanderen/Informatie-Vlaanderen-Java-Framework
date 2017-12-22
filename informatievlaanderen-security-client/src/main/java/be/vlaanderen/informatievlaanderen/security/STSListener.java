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

package be.vlaanderen.informatievlaanderen.security;

/**
 * Secure Token Service Listener interface.
 * <p>
 * Can be used to listen to InformatieVlaanderenSecurity STS activity related. Because the
 * initial security protocol run can take a while, it might be handy for some
 * applications to be able to receive some feedback on the progress.
 * 
 * @author Frank Cornelis
 * 
 */
public interface STSListener {

	/**
	 * Notifies on IP-STS token acquiring activity.
	 */
	void requestingIPSTSToken();

	/**
	 * Notifies on R-STS token acquiring activity.
	 */
	void requestingRSTSToken();

	/**
	 * Notifies on secure conversation token acquiring activity.
	 */
	void requestingSecureConversationToken();
}
