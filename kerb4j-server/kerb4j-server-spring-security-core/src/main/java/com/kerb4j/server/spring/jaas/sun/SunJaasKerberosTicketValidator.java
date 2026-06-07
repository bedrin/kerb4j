package com.kerb4j.server.spring.jaas.sun;

import com.kerb4j.client.SpnegoClient;
import com.kerb4j.client.SpnegoContext;
import com.kerb4j.server.MultiPrincipalManager;
import com.kerb4j.server.SpnegoTokenFixer;
import com.kerb4j.server.marshall.Kerb4JException;
import com.kerb4j.server.marshall.spnego.SpnegoInitToken;
import com.kerb4j.server.marshall.spnego.SpnegoKerberosMechToken;
import com.kerb4j.server.spring.KerberosTicketValidator;
import com.kerb4j.server.spring.SpnegoAuthenticationToken;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.Assert;

import java.io.IOException;
import java.security.PrivilegedActionException;

/**
 * Implementation of {@link KerberosTicketValidator} which uses the SUN JAAS
 * login module, which is included in the SUN JRE, it will not work with an IBM JRE.
 * The whole configuration is done in this class, no additional JAAS configuration
 * is needed.
 *
 * @author Mike Wiesner
 * @author Jeremy Stone
 */
@NullMarked
public class SunJaasKerberosTicketValidator implements KerberosTicketValidator, InitializingBean {

    private static final Log LOG = LogFactory.getLog(SunJaasKerberosTicketValidator.class);

    private @Nullable String servicePrincipal;
    private @Nullable String servicePassword;
    private @Nullable Resource keyTabLocation;

    private boolean acceptOnly;

    private @Nullable SpnegoClient spnegoClient;
    
    // Multi-principal support
    private @Nullable MultiPrincipalManager multiPrincipalManager;

    private boolean holdOnToGSSContext;


    @Override
    public SpnegoAuthenticationToken validateTicket(byte[] token) {

        SpnegoTokenFixer.fix(token);

        try {
            SpnegoClient clientToUse = resolveSpnegoClient(token);
            if (clientToUse == null) {
                throw new BadCredentialsException("Kerberos validation not successful");
            }

            SpnegoContext acceptContext = clientToUse.createAcceptContext();
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
                SpnegoInitToken spnegoInitToken = new SpnegoInitToken(token);
                SpnegoKerberosMechToken spnegoKerberosMechToken = spnegoInitToken.getSpnegoKerberosMechToken();
                encryptionType = spnegoKerberosMechToken.getApRequest().getTicket().getEncryptedEncPart().getEType();
            } catch (Kerb4JException e) {
                LOG.error("Failed to extract etype from spnego token", e);
            }

            return new SpnegoAuthenticationToken(
                    token,
                    srcName.toString(),
                    responseToken,
                    clientToUse.getSubject(),
                    clientToUse.getKerberosKeys(),
                    null == encryptionType ? null : encryptionType.getName()
            );
            // TODO: check that it doesn't involve network

        } catch (IOException | GSSException | PrivilegedActionException e) {
            throw new BadCredentialsException("Kerberos validation not successful", e);
        }

    }

    @Override
    public void afterPropertiesSet() throws Exception {
        boolean hasMultiPrincipal = multiPrincipalManager != null;
        boolean hasSinglePrincipal = this.servicePrincipal != null
                && (this.keyTabLocation != null || this.servicePassword != null);

        Assert.state(hasMultiPrincipal || hasSinglePrincipal,
                "Either multiPrincipalManager or servicePrincipal (with keyTabLocation or servicePassword) must be configured");

        if (hasMultiPrincipal) {
            int configuredPrincipalCount = multiPrincipalManager.getConfiguredSpns().size();
            Assert.state(configuredPrincipalCount > 0, "At least one principal must be configured in multiPrincipalManager");
            LOG.info("Ticket validator initialized with multi-principal support for "
                    + configuredPrincipalCount + " principals");
            if (hasSinglePrincipal) {
                LOG.warn("servicePrincipal/keyTabLocation configuration is ignored when multiPrincipalManager is set. "
                        + "Configure fallback via MultiPrincipalManager instead.");
            }
        } else if (hasSinglePrincipal) {
            String configuredServicePrincipal = this.servicePrincipal;
            Assert.state(configuredServicePrincipal != null, "servicePrincipal must be specified");
            Assert.state(null != this.keyTabLocation || null != this.servicePassword,
                    "Either servicePassword or keyTabLocation must be specified");
            if (null != this.keyTabLocation) {
                if (keyTabLocation instanceof ClassPathResource) {
                    LOG.warn("Your keytab is in the classpath. This file needs special protection and shouldn't be in the classpath. JAAS may also not be able to load this file from classpath.");
                }
                String keyTabLocationAsString = this.keyTabLocation.getURL().toExternalForm();
                // We need to remove the file prefix (if there is one), as it is not supported in Java 7 anymore.
                // As Java 6 accepts it with and without the prefix, we don't need to check for Java 7
                if (keyTabLocationAsString.startsWith("file:")) {
                    keyTabLocationAsString = keyTabLocationAsString.substring(5);
                }

                spnegoClient = SpnegoClient.loginWithKeyTab(configuredServicePrincipal, keyTabLocationAsString, acceptOnly);
            } else {
                String configuredServicePassword = this.servicePassword;
                Assert.state(configuredServicePassword != null, "servicePassword must be specified");
                spnegoClient = SpnegoClient.loginWithUsernamePassword(configuredServicePrincipal, configuredServicePassword);
            }
        }
    }

    /**
     * The service principal of the application.
     * For web apps this is <code>HTTP/full-qualified-domain-name@DOMAIN</code>.
     * todo: add warning on UPN
     * The keytab must contain the key for this principal.
     *
     * @param servicePrincipal service principal to use
     * @see #setKeyTabLocation(Resource)
     */
    public void setServicePrincipal(@Nullable String servicePrincipal) {
        this.servicePrincipal = servicePrincipal;
    }

    /**
     * <p>The location of the keytab. You can use the normale Spring Resource
     * prefixes like <code>file:</code> or <code>classpath:</code>, but as the
     * file is later on read by JAAS, we cannot guarantee that <code>classpath</code>
     * works in every environment, esp. not in Java EE application servers. You
     * should use <code>file:</code> there.
     * <p>
     * This file also needs special protection, which is another reason to
     * not include it in the classpath but rather use <code>file:/etc/http.keytab</code>
     * for example.
     *
     * @param keyTabLocation The location where the keytab resides
     */
    public void setKeyTabLocation(@Nullable Resource keyTabLocation) {
        this.keyTabLocation = keyTabLocation;
    }

    public void setServicePassword(@Nullable String servicePassword) {
        this.servicePassword = servicePassword;
    }

    /**
     * Determines whether to hold on to the {@link GSSContext GSS security context} or
     * otherwise {@link GSSContext#dispose() dispose} of it immediately (the default behaviour).
     * <p>Holding on to the GSS context allows decrypt and encrypt operations for subsequent
     * interactions with the principal.
     *
     * @param holdOnToGSSContext true if should hold on to context
     */
    public void setHoldOnToGSSContext(boolean holdOnToGSSContext) {
        this.holdOnToGSSContext = holdOnToGSSContext;
    }

    /**
     * @since 0.1.3
     */
    public void setAcceptOnly(boolean acceptOnly) {
        this.acceptOnly = acceptOnly;
    }
    
    /**
     * Set the multi-principal manager for handling multiple service principals.
     * When this is set, the validator will extract the target SPN from incoming tokens
     * and select the appropriate principal for validation.
     * 
     * @param multiPrincipalManager the multi-principal manager
     */
    public void setMultiPrincipalManager(@Nullable MultiPrincipalManager multiPrincipalManager) {
        this.multiPrincipalManager = multiPrincipalManager;
    }

    private @Nullable SpnegoClient resolveSpnegoClient(byte[] token) {
        MultiPrincipalManager configuredManager = multiPrincipalManager;
        if (configuredManager == null) {
            return spnegoClient;
        }
        String targetSpn = extractTargetSpn(token);
        SpnegoClient selectedClient = configuredManager.getSpnegoClientForSpn(targetSpn);
        if (selectedClient == null) {
            if (targetSpn == null) {
                throw new BadCredentialsException(
                        "Failed to extract SPN from token and no matching/fallback principal is configured");
            }
            throw new BadCredentialsException("No principal configured for SPN: " + targetSpn);
        }
        return selectedClient;
    }

    private @Nullable String extractTargetSpn(byte[] token) {
        try {
            SpnegoInitToken spnegoInitToken = new SpnegoInitToken(token);
            String targetSpn = spnegoInitToken.getServerPrincipalName();
            LOG.debug("Extracted target SPN from token: " + targetSpn);
            return targetSpn;
        } catch (Kerb4JException e) {
            LOG.debug("Failed to extract SPN from token", e);
            return null;
        }
    }
}