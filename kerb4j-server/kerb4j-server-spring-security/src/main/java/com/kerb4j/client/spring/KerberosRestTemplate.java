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

import com.kerb4j.common.util.Constants;
import com.kerb4j.common.util.base64.Base64Codec;
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
import java.util.List;

/**
 * {@code RestTemplate} that is able to make kerberos authenticated REST
 * requests passing the credentials in Basic authorization header.
 * <p>
 * TODO update documentations
 */
public class KerberosRestTemplate extends RestTemplate {

    private final String authorizationHeader;

    public KerberosRestTemplate(String username, String password) {
        authorizationHeader = getAuthorizationHeader(username, password);
    }

    public KerberosRestTemplate(ClientHttpRequestFactory requestFactory, String username, String password) {
        super(requestFactory);
        authorizationHeader = getAuthorizationHeader(username, password);
    }

    public KerberosRestTemplate(List<HttpMessageConverter<?>> messageConverters, String username, String password) {
        super(messageConverters);
        authorizationHeader = getAuthorizationHeader(username, password);
    }

    private static String getAuthorizationHeader(String username, String password) {
        return "Basic " + Base64Codec.encode((username + ":" + password).getBytes());
    }

    @Override
    protected <T> T doExecute(final URI uri, final HttpMethod method, final RequestCallback requestCallback, final ResponseExtractor<T> responseExtractor) throws RestClientException {
        return super.doExecute(uri, method, new RequestCallback() {
            @Override
            public void doWithRequest(ClientHttpRequest request) throws IOException {

                requestCallback.doWithRequest(request);

                request.getHeaders().add(Constants.AUTHZ_HEADER, authorizationHeader);

            }
        }, responseExtractor);
    }

}
