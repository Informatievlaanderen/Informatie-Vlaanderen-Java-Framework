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

import java.util.List;

import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;
import javax.xml.ws.soap.AddressingFeature;

import org.junit.Test;
import be.vlaanderen.informatievlaanderen.security.jaxb.mex.GetMetadata;
import be.vlaanderen.informatievlaanderen.security.jaxb.mex.Metadata;
import be.vlaanderen.informatievlaanderen.security.jaxws.mex.MetadataExchange;
import be.vlaanderen.informatievlaanderen.security.jaxws.mex.MetadataExchangeService;
import be.vlaanderen.informatievlaanderen.security.jaxb.mex.ObjectFactory;

import be.vlaanderen.informatievlaanderen.security.handler.LoggingHandler;

public class MetadataExchangeTest {

	@Test
	public void testGetMetadata() {
		MetadataExchangeService metadataExchangeService = new MetadataExchangeService();
		MetadataExchange metadataExchange = metadataExchangeService
				.getMetadataExchangePort(new AddressingFeature());

		BindingProvider bindingProvider = (BindingProvider) metadataExchange;
		bindingProvider
				.getRequestContext()
				.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY,
						"https://beta.auth.vlaanderen.be/ipsts/Services/DaliSecurityTokenServiceConfiguration.svc/mex");

		Binding binding = bindingProvider.getBinding();
		List<Handler> handlerChain = binding.getHandlerChain();
		handlerChain.add(new LoggingHandler());
		binding.setHandlerChain(handlerChain);

		ObjectFactory objectFactory = new ObjectFactory();
		GetMetadata body = objectFactory.createGetMetadata();
		Metadata metadata = metadataExchange.getMetadata(body);
	}
}
