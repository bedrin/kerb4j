package com.kerb4j.server.spring;

import org.springframework.security.authentication.BadCredentialsException;

/**
 * Implementations of this interface are used in
 * {@link SpnegoAuthenticationProvider} to validate a Kerberos/SPNEGO
 * Ticket.
 *
 * @author Mike Wiesner
 * @author Jeremy Stone
 * @see SpnegoAuthenticationProvider
 */
public interface KerberosTicketValidator {

    /**
     * Validates a Kerberos/SPNEGO ticket.
     *
     * @param token Kerbeos/SPNEGO ticket
     * @return authenticated kerberos principal
     * @throws BadCredentialsException if the ticket is not valid
     */
    SpnegoAuthenticationToken validateTicket(byte[] token)
            throws BadCredentialsException;

}
