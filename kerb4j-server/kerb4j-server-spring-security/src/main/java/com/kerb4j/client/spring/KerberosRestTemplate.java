package com.kerb4j.client.spring;

import com.kerb4j.common.util.Constants;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
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
        return "Basic " + Base64.getEncoder().encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
    }

    @Override
    protected <T> T doExecute(final URI uri, final String uriTemplate, final HttpMethod method, final RequestCallback requestCallback,
                              final ResponseExtractor<T> responseExtractor) throws RestClientException {
        return super.doExecute(uri, uriTemplate, method, request -> {
            requestCallback.doWithRequest(request);
            request.getHeaders().add(Constants.AUTHZ_HEADER, authorizationHeader);
        }, responseExtractor);
    }

}
