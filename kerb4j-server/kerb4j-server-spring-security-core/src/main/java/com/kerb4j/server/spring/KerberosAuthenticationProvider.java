package com.kerb4j.server.spring;

import com.kerb4j.client.SpnegoClient;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * {@link AuthenticationProvider} for kerberos.
 *
 * @author Mike Wiesner
 */
public class KerberosAuthenticationProvider implements AuthenticationProvider {

    private UserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UsernamePasswordAuthenticationToken auth = (UsernamePasswordAuthenticationToken) authentication;
        String validatedUsername;

        SpnegoClient spnegoClient = SpnegoClient.
                loginWithUsernamePassword(auth.getName(), auth.getCredentials().toString());
        spnegoClient.getSubject();
        validatedUsername = auth.getName(); // TODO: take from spnegoClient instead ?

        UserDetails userDetails = this.userDetailsService.loadUserByUsername(validatedUsername);
        UsernamePasswordAuthenticationToken output = new UsernamePasswordAuthenticationToken(userDetails,
                auth.getCredentials(), userDetails.getAuthorities());
        output.setDetails(authentication.getDetails());
        return output;

    }

    @Override
    public boolean supports(Class<? extends Object> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }

    /**
     * Sets the user details service.
     *
     * @param detailsService the new user details service
     */
    public void setUserDetailsService(UserDetailsService detailsService) {
        this.userDetailsService = detailsService;
    }

}
