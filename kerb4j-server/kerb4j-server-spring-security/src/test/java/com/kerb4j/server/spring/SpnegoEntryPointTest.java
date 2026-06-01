package com.kerb4j.server.spring;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.*;

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
