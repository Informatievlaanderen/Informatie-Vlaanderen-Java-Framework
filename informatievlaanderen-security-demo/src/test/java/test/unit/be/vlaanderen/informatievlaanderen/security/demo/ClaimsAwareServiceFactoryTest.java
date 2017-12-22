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

package test.unit.be.vlaanderen.informatievlaanderen.security.demo;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;
import org.tempuri.Service;

import be.vlaanderen.informatievlaanderen.security.demo.ClaimsAwareServiceFactory;

public class ClaimsAwareServiceFactoryTest {

	@Test
	public void testGetInstance() {
		// operate
		Service service = ClaimsAwareServiceFactory.getInstance();

		// verify
		assertNotNull(service);
	}
	
	@Test
	public void testGetInstanceNoWSPolicy() {
		// operate
		Service service = ClaimsAwareServiceFactory.getInstanceNoWSPolicy();

		// verify
		assertNotNull(service);
	}
}
