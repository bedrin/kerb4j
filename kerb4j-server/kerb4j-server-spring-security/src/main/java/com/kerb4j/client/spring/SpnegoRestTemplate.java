/*
 * Copyright 2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.kerb4j.client.spring;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.client.SpnegoContext;
import com.kerb4j.common.util.Constants;
import org.ietf.jgss.GSSException;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.security.PrivilegedActionException;
import java.util.List;

/**
 * {@code RestTemplate} that is able to make kerberos SPNEGO authenticated REST
 * requests. Under a hood this {@code SpnegoRestTemplate} is using {@link SpnegoClient} to
 * support Kerberos.
 *
 * TODO update documentations
 * <p>Generally this template can be configured in few different ways.
 * <ul>
 *   <li>Leave keyTabLocation and userPrincipal empty if you want to use cached ticket</li>
 *   <li>Use keyTabLocation and userPrincipal if you want to use keytab file</li>
 *   <li>Use loginOptions if you want to customise Krb5LoginModule options</li>
 *   <li>Use a customised httpClient</li>
 * </ul>
 *
 * @author Janne Valkealahti
 *
 */
public class SpnegoRestTemplate extends RestTemplate {

	private final SpnegoClient spnegoClient;

	// TODO: add URL to SPN mapper function, or cache

	/**
	 * Instantiates a new kerberos rest template.
	 */
	public SpnegoRestTemplate(SpnegoClient spnegoClient) {
		this.spnegoClient = spnegoClient;
	}

	public SpnegoRestTemplate(ClientHttpRequestFactory requestFactory, SpnegoClient spnegoClient) {
		super(requestFactory);
		this.spnegoClient = spnegoClient;
	}

	public SpnegoRestTemplate(List<HttpMessageConverter<?>> messageConverters, SpnegoClient spnegoClient) {
		super(messageConverters);
		this.spnegoClient = spnegoClient;
	}

	@Override
	protected <T> T doExecute(final URI uri, final HttpMethod method, final RequestCallback requestCallback, final ResponseExtractor<T> responseExtractor) throws RestClientException {
		return super.doExecute(uri, method, new RequestCallback() {
			@Override
			public void doWithRequest(ClientHttpRequest request) throws IOException {

				requestCallback.doWithRequest(request);

				// TODO: process response if required
				try {
					SpnegoContext spnegoContext = spnegoClient.createContext(uri.toURL());
					request.getHeaders().add(Constants.AUTHZ_HEADER, spnegoContext.createTokenAsAuthroizationHeader());
				} catch (PrivilegedActionException | GSSException e) {
					throw new IOException(e);
				}

			}
		}, responseExtractor);
	}

}
