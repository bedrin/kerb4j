package org.springframework.security.kerberos.web.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.kerberos.authentication.KerberosServiceRequestToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;

public class ResponseHeaderSettingKerberosAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        if (authentication instanceof KerberosServiceRequestToken kerberosToken && kerberosToken.hasResponseToken()) {
            response.setHeader("WWW-Authenticate", "Negotiate "
                    + Base64.getEncoder().encodeToString(kerberosToken.getTicketValidation().responseToken()));
        }
    }
}
