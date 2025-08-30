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
package com.kerb4j.server.spring.jaas.sun;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.client.SpnegoContext;
import com.kerb4j.server.SpnegoTokenFixer;
import com.kerb4j.server.marshall.Kerb4JException;
import com.kerb4j.server.marshall.spnego.SpnegoInitToken;
import com.kerb4j.server.spring.KerberosTicketValidator;
import com.kerb4j.server.spring.MultiPrincipalManager;
import com.kerb4j.server.spring.SpnegoAuthenticationToken;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.Assert;

import java.io.IOException;
import java.security.PrivilegedActionException;

/**
 * Multi-principal version of SunJaasKerberosTicketValidator that can handle
 * multiple service principals. It extracts the target SPN from the SPNEGO token
 * and selects the appropriate principal for validation.
 * 
 * @since 2.0.0
 */
public class MultiPrincipalSunJaasKerberosTicketValidator implements KerberosTicketValidator, InitializingBean {

    private static final Log LOG = LogFactory.getLog(MultiPrincipalSunJaasKerberosTicketValidator.class);

    private MultiPrincipalManager multiPrincipalManager;
    private boolean holdOnToGSSContext;

    @Override
    public SpnegoAuthenticationToken validateTicket(byte[] token) {
        SpnegoTokenFixer.fix(token);

        try {
            // First, extract the target SPN from the token
            SpnegoInitToken spnegoInitToken = new SpnegoInitToken(token);
            String targetSPN = spnegoInitToken.getServerPrincipalName();
            
            LOG.debug("Extracted target SPN from token: " + targetSPN);
            
            // Get the appropriate SpnegoClient for this SPN
            SpnegoClient spnegoClient = multiPrincipalManager.getSpnegoClientForSPN(targetSPN);
            if (spnegoClient == null) {
                throw new BadCredentialsException("No principal configured for SPN: " + targetSPN);
            }
            
            LOG.debug("Using SpnegoClient for SPN: " + targetSPN);
            
            SpnegoContext acceptContext = spnegoClient.createAcceptContext();
            byte[] responseToken = acceptContext.acceptToken(token);
            GSSName srcName = acceptContext.getSrcName();

            if (null == srcName) {
                throw new BadCredentialsException("Kerberos validation not successful");
            }

            if (!holdOnToGSSContext) {
                acceptContext.close();
            }

            EncryptionType encryptionType = null;

            try {
                encryptionType = spnegoInitToken.getSpnegoKerberosMechToken().getApRequest().getTicket().getEncryptedEncPart().getEType();
            } catch (Kerb4JException e) {
                LOG.error("Failed to extract etype from spnego token", e);
            }

            return new SpnegoAuthenticationToken(
                    token,
                    srcName.toString(),
                    responseToken,
                    spnegoClient.getSubject(),
                    spnegoClient.getKerberosKeys(),
                    null == encryptionType ? null : encryptionType.getName()
            );

        } catch (IOException | GSSException | PrivilegedActionException | Kerb4JException e) {
            throw new BadCredentialsException("Kerberos validation not successful", e);
        }
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.multiPrincipalManager, "multiPrincipalManager must be specified");
        String[] spns = multiPrincipalManager.getConfiguredSPNs();
        Assert.state(spns.length > 0, "At least one principal must be configured");
        LOG.info("Multi-principal ticket validator initialized with " + spns.length + " principals");
    }

    /**
     * Set the multi-principal manager that provides SpnegoClients for different SPNs.
     * 
     * @param multiPrincipalManager the multi-principal manager
     */
    public void setMultiPrincipalManager(MultiPrincipalManager multiPrincipalManager) {
        this.multiPrincipalManager = multiPrincipalManager;
    }

    /**
     * Determines whether to hold on to the {@link org.ietf.jgss.GSSContext GSS security context} or
     * otherwise {@link org.ietf.jgss.GSSContext#dispose() dispose} of it immediately (the default behaviour).
     * <p>Holding on to the GSS context allows decrypt and encrypt operations for subsequent
     * interactions with the principal.
     *
     * @param holdOnToGSSContext true if should hold on to context
     */
    public void setHoldOnToGSSContext(boolean holdOnToGSSContext) {
        this.holdOnToGSSContext = holdOnToGSSContext;
    }
}