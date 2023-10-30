/*
 * Copyright 2009-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.kerb4j.server.spring;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test class for {@link SpnegoEntryPoint}
 *
 * @author Mike Wiesner
 * @author Janne Valkealahti
 * @author Andre Schaefer, Namics AG
 * @since 1.0
 */
class SpnegoEntryPointTest {

    private final SpnegoEntryPoint entryPoint = new SpnegoEntryPoint();

    @Test
    void testEntryPointOk() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        entryPoint.commence(request, response, null);

        verify(response).addHeader("WWW-Authenticate", "Negotiate");
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @Test
    void testEntryPointOkWithDispatcher() throws Exception {
        SpnegoEntryPoint entryPoint = new SpnegoEntryPoint();
        HttpServletResponse response = mock(HttpServletResponse.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        RequestDispatcher requestDispatcher = mock(RequestDispatcher.class);
        when(request.getRequestDispatcher(anyString())).thenReturn(requestDispatcher);
        entryPoint.commence(request, response, null);
        verify(response).addHeader("WWW-Authenticate", "Negotiate");
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @Test
    void testEntryPointForwardOk() throws Exception {
        String forwardUrl = "/login";
        SpnegoEntryPoint entryPoint = new SpnegoEntryPoint(forwardUrl);
        HttpServletResponse response = mock(HttpServletResponse.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        RequestDispatcher requestDispatcher = mock(RequestDispatcher.class);
        when(request.getRequestDispatcher(anyString())).thenReturn(requestDispatcher);
        entryPoint.commence(request, response, null);
        verify(response).addHeader("WWW-Authenticate", "Negotiate");
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        verify(request).getRequestDispatcher(forwardUrl);
        verify(requestDispatcher).forward(request, response);
    }

    @Test
    void testEntryPointForwardAbsolute() {
        IllegalArgumentException exception = Assertions.assertThrows(
                IllegalArgumentException.class, () -> new SpnegoEntryPoint("http://test/login")
        );
        Assertions.assertNotNull(exception);
    }

}
