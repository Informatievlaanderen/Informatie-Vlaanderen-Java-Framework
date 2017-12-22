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

package test.unit.be.vlaanderen.informatievlaanderen.security.client;

import javax.xml.transform.TransformerException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Constants;
import org.apache.xpath.XPathAPI;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import be.vlaanderen.informatievlaanderen.security.client.WSConstants;

public class TestUtils {

	private static final Log LOG = LogFactory.getLog(TestUtils.class);

	/**
	 * XMLSEC 1.5 requires us to explicitly mark the Id's within a DOM document.
	 * 
	 * @param document
	 */
	public static void markAllIdAttributesAsId(Document document) {
		Element nsElement = document.createElement("nsElement");
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:wsu",
				WSConstants.WS_SECURITY_UTILITY_NAMESPACE);

		NodeList elementsWithIdNodeList;
		try {
			elementsWithIdNodeList = XPathAPI.selectNodeList(document,
					"//*[@Id or @wsu:Id]", nsElement);
		} catch (TransformerException e) {
			throw new RuntimeException(e);
		}

		for (int nodeIdx = 0; nodeIdx < elementsWithIdNodeList.getLength(); nodeIdx++) {
			Element elementWithId = (Element) elementsWithIdNodeList
					.item(nodeIdx);
			LOG.debug("element with Id: " + elementWithId.getLocalName());
			Attr attributeNode = elementWithId.getAttributeNode("Id");
			if (null == attributeNode) {
				attributeNode = elementWithId.getAttributeNodeNS(
						WSConstants.WS_SECURITY_UTILITY_NAMESPACE, "Id");
			}
			elementWithId.setIdAttributeNode(attributeNode, true);
		}
	}
}
