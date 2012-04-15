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

package be.agiv.security.client;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.Proxy.Type;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Proxy selector implementation for AGIV Security framework.
 * 
 * @author Frank Cornelis
 * 
 */
public class ClientProxySelector extends ProxySelector {

	private static final Log LOG = LogFactory.getLog(ClientProxySelector.class);

	private final ProxySelector defaultProxySelector;

	private final Map<String, Proxy> proxies;

	/**
	 * Main constructor. Delegates unknown host requests to the given default
	 * proxy selector.
	 * 
	 * @param defaultProxySelector
	 *            the default proxy selector.
	 */
	public ClientProxySelector(ProxySelector defaultProxySelector) {
		this.defaultProxySelector = defaultProxySelector;
		this.proxies = new ConcurrentHashMap<String, Proxy>();
	}

	@Override
	public List<Proxy> select(URI uri) {
		LOG.debug("select for: " + uri);
		String hostname = uri.getHost();
		Proxy proxy = this.proxies.get(hostname);
		if (null != proxy) {
			LOG.debug("using proxy: " + proxy);
			return Collections.singletonList(proxy);
		}
		if (null != this.defaultProxySelector) {
			return this.defaultProxySelector.select(uri);
		}
		return Collections.singletonList(Proxy.NO_PROXY);
	}

	@Override
	public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
		LOG.warn("connection failed for: " + uri);
		if (null != this.defaultProxySelector) {
			this.defaultProxySelector.connectFailed(uri, sa, ioe);
		}
	}

	/**
	 * Sets the proxy for the (hostname of the) given location.
	 * 
	 * @param location
	 *            the location on which the proxy settings apply.
	 * @param proxyHost
	 *            the host of the proxy.
	 * @param proxyPort
	 *            the port of the proxy.
	 * @param proxyType
	 *            the type of the proxy.
	 */
	public void setProxy(String location, String proxyHost, int proxyPort,
			Type proxyType) {
		String hostname;
		try {
			hostname = new URL(location).getHost();
		} catch (MalformedURLException e) {
			throw new RuntimeException("URL error: " + e.getMessage(), e);
		}
		if (null == proxyHost) {
			LOG.debug("removing proxy for: " + hostname);
			this.proxies.remove(hostname);
		} else {
			LOG.debug("setting proxy for: " + hostname);
			this.proxies.put(hostname, new Proxy(proxyType,
					new InetSocketAddress(proxyHost, proxyPort)));
		}
	}
}
