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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.Proxy;
import java.net.ProxySelector;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;
import javax.xml.ws.soap.SOAPFaultException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.joda.time.Duration;

import be.agiv.security.client.ClientProxySelector;
import be.agiv.security.client.IPSTSClient;
import be.agiv.security.client.RSTSClient;
import be.agiv.security.client.SecureConversationClient;
import be.agiv.security.handler.AGIVSOAPHandler;
import be.agiv.security.handler.AuthenticationHandler;
import be.agiv.security.handler.LoggingHandler;
import be.agiv.security.handler.SecureConversationHandler;
import be.agiv.security.handler.SecurityTokenConsumer;
import be.agiv.security.handler.SecurityTokenProvider;
import be.agiv.security.handler.WSSecurityHandler;

/**
 * The main AGIV security framework component.
 * <p/>
 * Basically you use the {@link AGIVSecurity#enable(BindingProvider)} method (or
 * one of its variants) to enable the AGIV Security framework on the JAX-WS
 * stubs.
 * <p/>
 * An AGIV security component holds all information to be able to connect to
 * AGIV secured web services. Although JAX-WS itself is not multi-threaded, this
 * component can be shared between different JAX-WS clients. Each AGIV security
 * component also caches the different obtained security tokens for as long as
 * they are valid, or explicitly cancelled. The AGIV security component also
 * manages the network proxy settings.
 * 
 * @author Frank Cornelis
 * 
 */
public class AGIVSecurity implements SecurityTokenProvider {

	private static final Log LOG = LogFactory.getLog(AGIVSecurity.class);

	public static final long DEFAULT_TOKEN_RETIREMENT_DURATION = 1000 * 60 * 5;

	public static final String BETA_REALM = "urn:agiv.be/salvador";

	public static final String PRODUCTION_REALM = "urn:agiv.be/sts";

	private final String ipStsLocation;

	private final ExternalIPSTSClient externalIpStsClient;

	private final String rStsLocation;

	private final String username;

	private final String password;

	private final X509Certificate certificate;

	private final PrivateKey privateKey;

	private final Map<String, SecurityToken> secureConversationTokens;

	private SecurityToken ipStsSecurityToken;

	private final Map<String, SecurityToken> rStsSecurityTokens;

	private static ClientProxySelector clientProxySelector;

	private String proxyHost;
	private int proxyPort;
	private Proxy.Type proxyType;

	private long tokenRetirementDuration = DEFAULT_TOKEN_RETIREMENT_DURATION;

	private final List<STSListener> stsListeners;

	private final String rStsRealm;

	static {
		ProxySelector defaultProxySelector = ProxySelector.getDefault();
		AGIVSecurity.clientProxySelector = new ClientProxySelector(
				defaultProxySelector);
		ProxySelector.setDefault(AGIVSecurity.clientProxySelector);
	}

	/**
	 * Main constructor. This constructor assumes the usage of username/password
	 * credentials.
	 * 
	 * @param ipStsLocation
	 *            the location of the IP-STS WS-Trust web service.
	 * @param rStsLocation
	 *            the location of the R-STS WS-Trust web service.
	 * @param rStsRealm
	 *            the AGIV R-STS realm.
	 * @param username
	 *            the username client credential
	 * @param password
	 *            the password client credential.
	 */
	public AGIVSecurity(String ipStsLocation, String rStsLocation,
			String rStsRealm, String username, String password) {
		this(ipStsLocation, rStsLocation, rStsRealm, username, password, null,
				null, null);
	}

	/**
	 * Constructor for X509 credentials.
	 * 
	 * @param ipStsLocation
	 *            the location of the IP-STS WS-Trust web service.
	 * @param rStsLocation
	 *            the location of the R-STS WS-Trust web service.
	 * @param rStsRealm
	 *            the AGIV R-STS realm.
	 * @param certificate
	 *            the X509 certificate credential.
	 * @param privateKey
	 *            the corresponding private RSA key.
	 * @see AGIVSecurity#AGIVSecurity(String, String, File, String)
	 */
	public AGIVSecurity(String ipStsLocation, String rStsLocation,
			String rStsRealm, X509Certificate certificate, PrivateKey privateKey) {
		this(ipStsLocation, rStsLocation, rStsRealm, null, null, null,
				certificate, privateKey);
	}

	/**
	 * Constructor for X509 credentials. The certificate and corresponding
	 * private key are loaded from a PKCS#12 keystore file.
	 * 
	 * @param ipStsLocation
	 *            the location of the IP-STS WS-Trust web service.
	 * @param rStsLocation
	 *            the location of the R-STS WS-Trust web service.
	 * @param rStsRealm
	 *            the AGIV R-STS realm.
	 * @param pkcs12File
	 *            the PKCS#12 keystore file.
	 * @param pkcs12Password
	 *            the PKCS#12 keystore password.
	 * @throws SecurityException
	 *             gets thrown in case of a PKCS#12 keystore error.
	 * @see AGIVSecurity#AGIVSecurity(String, String, X509Certificate,
	 *      PrivateKey)
	 */
	public AGIVSecurity(String ipStsLocation, String rStsLocation,
			String rStsRealm, File pkcs12File, String pkcs12Password)
			throws SecurityException {
		this.ipStsLocation = ipStsLocation;
		this.rStsLocation = rStsLocation;
		this.rStsRealm = rStsRealm;
		this.username = null;
		this.password = null;

		InputStream pkcs12InputStream;
		try {
			pkcs12InputStream = new FileInputStream(pkcs12File);
		} catch (FileNotFoundException e) {
			throw new SecurityException("PKCS#12 file does not exist: "
					+ pkcs12File.getAbsolutePath());
		}
		Provider sunJSSEProvider = Security.getProvider("SunJSSE");
		try {
			KeyStore keyStore;
			if (null != sunJSSEProvider) {
				// avoid older BouncyCastle implementations
				keyStore = KeyStore.getInstance("PKCS12", sunJSSEProvider);
			} else {
				keyStore = KeyStore.getInstance("PKCS12");
			}
			keyStore.load(pkcs12InputStream, pkcs12Password.toCharArray());
			Enumeration<String> aliases = keyStore.aliases();
			String alias = aliases.nextElement();
			this.certificate = (X509Certificate) keyStore.getCertificate(alias);
			this.privateKey = (PrivateKey) keyStore.getKey(alias,
					pkcs12Password.toCharArray());
		} catch (Exception e) {
			LOG.error("error loading PKCS#12 keystore: " + e.getMessage(), e);
			throw new SecurityException("error loading PKCS#12 certificate: "
					+ e.getMessage(), e);
		}
		this.externalIpStsClient = null;
		this.secureConversationTokens = new ConcurrentHashMap<String, SecurityToken>();
		this.rStsSecurityTokens = new ConcurrentHashMap<String, SecurityToken>();
		this.stsListeners = new CopyOnWriteArrayList<STSListener>();
	}

	/**
	 * Constructor for external IP-STS services. Use this constructor for
	 * external IP-STS services that do not behave exactly like the AGIV IP-STS
	 * service.
	 * 
	 * @param externalIpStsClient
	 *            the external IP-STS service client to be used.
	 * @param rStsLocation
	 *            the location of the R-STS WS-Trust web service.
	 */
	public AGIVSecurity(ExternalIPSTSClient externalIpStsClient,
			String rStsLocation) {
		this(null, rStsLocation, null, null, null, externalIpStsClient, null,
				null);
	}

	private AGIVSecurity(String ipStsLocation, String rStsLocation,
			String rStsRealm, String username, String password,
			ExternalIPSTSClient externalIpStsClient,
			X509Certificate certificate, PrivateKey privateKey) {
		this.ipStsLocation = ipStsLocation;
		this.rStsLocation = rStsLocation;
		this.rStsRealm = rStsRealm;
		this.username = username;
		this.password = password;
		this.certificate = certificate;
		this.privateKey = privateKey;
		this.externalIpStsClient = externalIpStsClient;
		this.secureConversationTokens = new ConcurrentHashMap<String, SecurityToken>();
		this.rStsSecurityTokens = new ConcurrentHashMap<String, SecurityToken>();
		this.stsListeners = new CopyOnWriteArrayList<STSListener>();
	}

	/**
	 * Adds an STS Listener to this AGIV security instance. An STS Listener can
	 * be used to monitor the activity of the AGIVSecurity component related to
	 * the different STS services.
	 * 
	 * @param stsListener
	 *            the STS listener to be added.
	 * @see STSListener
	 */
	public void addSTSListener(STSListener stsListener) {
		this.stsListeners.add(stsListener);
	}

	/**
	 * Sets the proxy configuration to be used by this AGIV Security component.
	 * <p/>
	 * Even the JAX-WS enabled stubs will use the proxy settings.
	 * 
	 * @param proxyHost
	 *            the host of the proxy.
	 * @param proxyPort
	 *            the port of the proxy.
	 * @param proxyType
	 *            the type of the proxy.
	 */
	public synchronized void setProxy(String proxyHost, int proxyPort,
			Proxy.Type proxyType) {
		AGIVSecurity.clientProxySelector.setProxy(this.ipStsLocation,
				proxyHost, proxyPort, proxyType);
		AGIVSecurity.clientProxySelector.setProxy(this.rStsLocation, proxyHost,
				proxyPort, proxyType);
		this.proxyHost = proxyHost;
		this.proxyPort = proxyPort;
		this.proxyType = proxyType;
	}

	/**
	 * Enable the AGIV security on the given JAX-WS binding provider. Each
	 * JAX-WS port can be casted to a JAX-WS binding provider.
	 * <p/>
	 * It is no problem to call the enable method multiple times for a certain
	 * JAX-WS stub. This method will only decorate the AGIV Security framework
	 * once on the given JAX-WS stub. If the JAX-WS stub is already decorated by
	 * another AGIVSecurity instance a {@link SecurityException} will be thrown.
	 * <p/>
	 * JAX-WS stubs enabled via this method will not use WS-SecureConversation.
	 * 
	 * @param bindingProvider
	 *            the JAX-WS binding provider on which to enable the AGIV
	 *            security framework.
	 * @see AGIVSecurity#enable(BindingProvider, String)
	 * @see AGIVSecurity#enable(BindingProvider, String, String)
	 * @see AGIVSecurity#enable(BindingProvider, String, boolean)
	 * @see AGIVSecurity#enable(BindingProvider, String, boolean, String)
	 * @see AGIVSecurity#enable(BindingProvider, boolean)
	 * @see AGIVSecurity#disable(BindingProvider)
	 */
	public void enable(BindingProvider bindingProvider) {
		enable(bindingProvider, false, null);
	}

	/**
	 * Enable the AGIV security on the given JAX-WS binding provider. Each
	 * JAX-WS port can be casted to a JAX-WS binding provider.
	 * <p/>
	 * It is no problem to call the enable method multiple times for a certain
	 * JAX-WS stub. This method will only decorate the AGIV Security framework
	 * once on the given JAX-WS stub. If the JAX-WS stub is already decorated by
	 * another AGIVSecurity instance a {@link SecurityException} will be thrown.
	 * 
	 * @param bindingProvider
	 *            the JAX-WS binding provider on which to enable the AGIV
	 *            security framework.
	 * @param useWsSecureConversation
	 *            set to <code>true</code> if WS-SecureConversation should be
	 *            used.
	 * @param serviceRealm
	 *            the optional service realm.
	 * @see AGIVSecurity#enable(BindingProvider, String)
	 * @see AGIVSecurity#enable(BindingProvider, String, boolean)
	 * @see AGIVSecurity#disable(BindingProvider)
	 */
	public void enable(BindingProvider bindingProvider,
			boolean useWsSecureConversation, String serviceRealm) {
		Binding binding = bindingProvider.getBinding();
		List<Handler> handlerChain = binding.getHandlerChain();
		for (Handler handler : handlerChain) {
			if (handler instanceof SecureConversationHandler
					|| handler instanceof AuthenticationHandler) {
				LOG.warn("security already enabled");
				SecurityTokenConsumer securityTokenConsumer = (SecurityTokenConsumer) handler;
				if (this != securityTokenConsumer.getSecurityTokenProvider()) {
					throw new SecurityException(
							"security on JAX-WS stub already enabled by another AGIVSecurity instance");
				}
				return;
			}
		}
		WSSecurityHandler wsSecurityHandler = new WSSecurityHandler();
		if (useWsSecureConversation) {
			handlerChain.add(new SecureConversationHandler(this,
					wsSecurityHandler, serviceRealm));
		} else {
			handlerChain.add(new AuthenticationHandler(this, wsSecurityHandler,
					serviceRealm));
		}
		handlerChain.add(wsSecurityHandler);
		handlerChain.add(new LoggingHandler());
		binding.setHandlerChain(handlerChain);
	}

	/**
	 * Disable the AGIV Security framework on the given JAX-WS port.
	 * <p/>
	 * Can be used when the JAX-WS stubs are managed by some container and the
	 * container strategy is to pool JAX-WS stub instances.
	 * 
	 * @param bindingProvider
	 *            the JAX-WS port.
	 * @see AGIVSecurity#enable(BindingProvider)
	 * @see AGIVSecurity#enable(BindingProvider, String)
	 */
	public void disable(BindingProvider bindingProvider) {
		LOG.debug("disabling AGIV security...");
		Binding binding = bindingProvider.getBinding();
		List<Handler> handlerChain = binding.getHandlerChain();
		Iterator<Handler> handlerIterator = handlerChain.iterator();
		while (handlerIterator.hasNext()) {
			Handler handler = handlerIterator.next();
			if (handler instanceof AGIVSOAPHandler) {
				handlerIterator.remove();
				continue;
			}
		}
		binding.setHandlerChain(handlerChain);
	}

	/**
	 * Enable the AGIV security on the given JAX-WS binding provider. Each
	 * JAX-WS port can be casted to a JAX-WS binding provider. The JAX-WS port
	 * will also be configured to use the service at the given service location.
	 * 
	 * @param bindingProvider
	 *            the JAX-WS binding provider on which to enable the AGIV
	 *            security framework.
	 * @param serviceLocation
	 *            the location of the web service.
	 * @param useWsSecureConversation
	 *            set to <code>true</code> if WS-SecureConversation should be
	 *            used.
	 * @param serviceRealm
	 *            the optional service realm.
	 * @see AGIVSecurity#enable(BindingProvider)
	 * @see AGIVSecurity#disable(BindingProvider)
	 */
	public void enable(BindingProvider bindingProvider, String serviceLocation,
			boolean useWsSecureConversation, String serviceRealm) {
		bindingProvider.getRequestContext().put(
				BindingProvider.ENDPOINT_ADDRESS_PROPERTY, serviceLocation);
		enable(bindingProvider, useWsSecureConversation, serviceRealm);
	}

	/**
	 * Enable the AGIV security on the given JAX-WS binding provider. Each
	 * JAX-WS port can be casted to a JAX-WS binding provider. The JAX-WS port
	 * will also be configured to use the service at the given service location.
	 * <p/>
	 * JAX-WS stubs enabled via this method will not use WS-SecureConversation.
	 * 
	 * @param bindingProvider
	 *            the JAX-WS binding provider on which to enable the AGIV
	 *            security framework.
	 * @param serviceLocation
	 *            the location of the web service.
	 * @param serviceRealm
	 *            the optional service realm.
	 * @see AGIVSecurity#enable(BindingProvider)
	 * @see AGIVSecurity#enable(BindingProvider, boolean)
	 * @see AGIVSecurity#enable(BindingProvider, String, boolean)
	 * @see AGIVSecurity#disable(BindingProvider)
	 */
	public void enable(BindingProvider bindingProvider, String serviceLocation,
			String serviceRealm) {
		enable(bindingProvider, serviceLocation, false, serviceRealm);
	}

	/**
	 * Gives back the location of the IP-STS WS-Trust web service.
	 * 
	 * @return IP-STS location.
	 */
	public String getIpStsLocation() {
		return this.ipStsLocation;
	}

	/**
	 * Gives back the location of the R-STS WS-Trust web service.
	 * 
	 * @return R-STS location.
	 */
	public String getRStsLocation() {
		return this.rStsLocation;
	}

	/**
	 * Gives back the username credential. Can be <code>null</code> in case of
	 * an external IP-STS configuration, or on case of certificate based
	 * credentials.
	 * 
	 * @return the username credential.
	 */
	public String getUsername() {
		return this.username;
	}

	/**
	 * Gives back the X509 certificate credential. Can be <code>null</code> in
	 * case of an external IP-STS configuration, or in case of username/password
	 * credentials.
	 * 
	 * @return the X509 certificate.
	 */
	public X509Certificate getCertificate() {
		return this.certificate;
	}

	/**
	 * Gives back a map of secure conversation tokens, indexed via the location
	 * of the web service for which the tokens apply.
	 * <p/>
	 * The map can be empty if no WS-SecureConversation is used.
	 * 
	 * @return a map of secure conversation tokens indexed per web service
	 *         location.
	 */
	public Map<String, SecurityToken> getSecureConversationTokens() {
		return this.secureConversationTokens;
	}

	/**
	 * Prefetch all security tokens (IP-STS, R-STS and secure conversation
	 * token) for the given web service location. This method could be used
	 * within applications to improve the end user experience.
	 * 
	 * @param location
	 *            the web service location for which to prefetch tokens.
	 * @param the
	 *            service realm.
	 * @param useWsSecureConversation
	 *            set to <code>true</code> if the WS-SecureConversation token
	 *            should also be fetched.
	 * @see AGIVSecurity#prefetchTokens(String)
	 */
	public void prefetchTokens(String location, String serviceRealm,
			boolean useWsSecureConversation) {
		if (useWsSecureConversation) {
			getSecureConversationToken(location, serviceRealm);
		} else {
			getSecurityToken(serviceRealm);
		}
	}

	/**
	 * Prefetch all security tokens (IP-STS, R-STS) for the given web service
	 * location. This method could be used within applications to improve the
	 * end user experience.
	 * 
	 * @param location
	 *            the web service location for which to prefetch tokens.
	 * @param serviceRealm
	 *            the service realm.
	 * @see AGIVSecurity#prefetchTokens(String, boolean)
	 */
	public void prefetchTokens(String location, String serviceRealm) {
		prefetchTokens(location, serviceRealm, false);
	}

	/**
	 * Prefetch all security tokens (IP-STS, R-STS) for the given web service
	 * location. The location will be used as service realm.
	 * 
	 * @param location
	 *            the web service location for which to prefetch tokens.
	 */
	public void prefetchTokens(String location) {
		prefetchTokens(location, location, false);
	}

	/**
	 * Prefetch all security tokens (IP-STS, R-STS) for the given web service
	 * location. The location will be used as service realm.
	 * 
	 * @param location
	 *            the web service location for which to prefetch tokens.
	 * @param useWsSecureConversation
	 *            set to <code>true</code> if the WS-SecureConversation token
	 *            should also be fetched.
	 */
	public void prefetchTokens(String location, boolean useWsSecureConversation) {
		prefetchTokens(location, location, useWsSecureConversation);
	}

	private void notifyIPSTSListeners() {
		for (STSListener stsListener : this.stsListeners) {
			try {
				stsListener.requestingIPSTSToken();
			} catch (Exception e) {
				LOG.error("error calling STS listener: " + e.getMessage(), e);
			}
		}
	}

	private void notifyRSTSListeners() {
		for (STSListener stsListener : this.stsListeners) {
			try {
				stsListener.requestingRSTSToken();
			} catch (Exception e) {
				LOG.error("error calling STS listener: " + e.getMessage(), e);
			}
		}
	}

	private void notifySecureConversationListeners() {
		for (STSListener stsListener : this.stsListeners) {
			try {
				stsListener.requestingSecureConversationToken();
			} catch (Exception e) {
				LOG.error("error calling STS listener: " + e.getMessage(), e);
			}
		}
	}

	/**
	 * Gives back the secure conversation token for the given web service
	 * location. In case the token cache does not yet hold tokens for the given
	 * web service location, this method will fetch new tokens from IP-STS,
	 * R-STS, and the WS-SecureConversation enabled web service. This method
	 * might also notify the registered STS listeners in case of STS activity.
	 * 
	 * @param location
	 *            the location of the web service for which the token should
	 *            apply.
	 * @param the
	 *            service realm.
	 * @return the secure conversation token
	 */
	public SecurityToken getSecureConversationToken(String location,
			String serviceRealm) {
		SecurityToken secureConversationToken = this.secureConversationTokens
				.get(location);
		if (requireNewToken(secureConversationToken)) {
			AGIVSecurity.clientProxySelector.setProxy(location, this.proxyHost,
					this.proxyPort, this.proxyType);
			/*
			 * New clients here since JAX-WS is not thread safe.
			 */
			SecurityToken rStsSecurityToken = getSecurityToken(serviceRealm);

			notifySecureConversationListeners();
			SecureConversationClient secureConversationClient = new SecureConversationClient(
					location);
			secureConversationToken = secureConversationClient
					.getSecureConversationToken(rStsSecurityToken);

			this.secureConversationTokens
					.put(location, secureConversationToken);
		}
		return secureConversationToken;
	}

	public SecurityToken getSecurityToken(String serviceRealm) {
		SecurityToken rStsSecurityToken = this.rStsSecurityTokens
				.get(serviceRealm);
		if (false == requireNewToken(rStsSecurityToken)) {
			return rStsSecurityToken;
		}
		if (requireNewToken(this.ipStsSecurityToken)) {
			notifyIPSTSListeners();
			if (null != this.externalIpStsClient) {
				this.ipStsSecurityToken = this.externalIpStsClient
						.getSecurityToken();
			} else {
				AGIVSecurity.clientProxySelector.setProxy(this.ipStsLocation,
						this.proxyHost, this.proxyPort, this.proxyType);
				IPSTSClient ipStsClient = new IPSTSClient(this.ipStsLocation,
						this.rStsRealm);
				if (null != this.certificate) {
					this.ipStsSecurityToken = ipStsClient.getSecuritytoken(
							this.certificate, this.privateKey);
				} else {
					this.ipStsSecurityToken = ipStsClient.getSecurityToken(
							this.username, this.password);
				}
			}
		}
		notifyRSTSListeners();
		AGIVSecurity.clientProxySelector.setProxy(this.rStsLocation,
				this.proxyHost, this.proxyPort, this.proxyType);
		RSTSClient rStsClient = new RSTSClient(this.rStsLocation);
		rStsSecurityToken = rStsClient.getSecurityToken(
				this.ipStsSecurityToken, serviceRealm);
		this.rStsSecurityTokens.put(serviceRealm, rStsSecurityToken);
		return rStsSecurityToken;
	}

	private boolean requireNewToken(SecurityToken secureConversationToken) {
		if (null == secureConversationToken) {
			return true;
		}
		DateTime now = new DateTime();
		DateTime expires = new DateTime(secureConversationToken.getExpires());
		Duration duration = new Duration(now, expires);
		LOG.debug("token validity: " + duration);
		if (duration.isLongerThan(new Duration(this.tokenRetirementDuration))) {
			LOG.debug("reusing secure conversation token: "
					+ secureConversationToken.getAttachedReference());
			return false;
		}
		return true;
	}

	/**
	 * Cancels all secure conversation tokens currently present within the token
	 * cache. Cancelling tokens on the server-side reduces load on the AGIV web
	 * services.
	 */
	public void cancelSecureConversationTokens() {
		for (Map.Entry<String, SecurityToken> secureConversationTokenEntry : this.secureConversationTokens
				.entrySet()) {
			String location = secureConversationTokenEntry.getKey();
			SecurityToken secureConversationToken = secureConversationTokenEntry
					.getValue();
			this.secureConversationTokens.remove(location);
			LOG.debug("cancelling secure conversation token: "
					+ secureConversationToken.getAttachedReference());
			SecureConversationClient secureConversationClient = new SecureConversationClient(
					location);
			try {
				secureConversationClient
						.cancelSecureConversationToken(secureConversationToken);
			} catch (SOAPFaultException e) {
				// in case token is expired
				LOG.warn("SOAP fault: " + e.getMessage());
			}
		}
	}

	/**
	 * Gives back the duration in milliseconds that a token will be refreshed
	 * before its expiration. Default is 5 minutes (5 * 60 * 1000).
	 * 
	 * @return duration in milliseconds.
	 */
	public long getTokenRetirementDuration() {
		return this.tokenRetirementDuration;
	}

	/**
	 * Sets the duration in milliseconds that a token will be refreshed before
	 * its expiration.
	 * 
	 * @param tokenRetirementDuration
	 *            duration in milliseconds.
	 */
	public void setTokenRetirementDuration(long tokenRetirementDuration) {
		this.tokenRetirementDuration = tokenRetirementDuration;
	}

	/**
	 * Enable the AGIV security on the given JAX-WS binding provider. Each
	 * JAX-WS port can be casted to a JAX-WS binding provider.
	 * 
	 * @param bindingProvider
	 *            the JAX-WS binding provider on which to enable the AGIV
	 *            security framework.
	 * @param useWsSecureConversation
	 *            set to <code>true</code> if WS-SecureConversation should be
	 *            used.
	 * @see AGIVSecurity#enable(BindingProvider, boolean, String)
	 */
	public void enable(BindingProvider bindingProvider,
			boolean useWsSecureConversation) {
		enable(bindingProvider, useWsSecureConversation, null);
	}

	/**
	 * Enable the AGIV security on the given JAX-WS binding provider. Each
	 * JAX-WS port can be casted to a JAX-WS binding provider.
	 * 
	 * @param bindingProvider
	 *            the JAX-WS binding provider on which to enable the AGIV
	 *            security framework.
	 * @param serviceLocation
	 *            the service location.
	 * @see AGIVSecurity#enable(BindingProvider, String, String)
	 */
	public void enable(BindingProvider bindingProvider, String serviceLocation) {
		enable(bindingProvider, serviceLocation, null);
	}

	/**
	 * Enable the AGIV security on the given JAX-WS binding provider. Each
	 * JAX-WS port can be casted to a JAX-WS binding provider.
	 * 
	 * @param bindingProvider
	 *            the JAX-WS binding provider on which to enable the AGIV
	 *            security framework.
	 * @param serviceLocation
	 *            the service location.
	 * @param useWsSecureConversation
	 *            set to <code>true</code> if WS-SecureConversation should be
	 *            used.
	 * @see AGIVSecurity#enable(BindingProvider, String, String)
	 */
	public void enable(BindingProvider bindingProvider, String serviceLocation,
			boolean useWsSecureConversation) {
		enable(bindingProvider, serviceLocation, useWsSecureConversation, null);
	}
}
