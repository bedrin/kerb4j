package org.jaaslounge.sso.oas.spnego;

import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.NamingException;
import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import oracle.security.jazn.asserter.AsserterException;
import oracle.security.jazn.asserter.TokenAsserter;
import oracle.security.jazn.callback.IdentityCallbackHandler;
import oracle.security.jazn.callback.IdentityCallbackHandlerImpl;
import oracle.security.jazn.token.HttpRequestIdentityToken;
import oracle.security.jazn.token.IdentityToken;
import oracle.security.jazn.util.SecurityLogger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.ietf.jgss.GSSException;
import org.jaaslounge.AuthenticatedUser;
import org.jaaslounge.GroupPrincipal;
import org.jaaslounge.UserPrincipal;
import org.jaaslounge.decoding.DecodingException;
import org.jaaslounge.decoding.kerberos.KerberosAuthData;
import org.jaaslounge.decoding.kerberos.KerberosPacAuthData;
import org.jaaslounge.decoding.kerberos.KerberosToken;
import org.jaaslounge.decoding.pac.PacLogonInfo;
import org.jaaslounge.decoding.pac.PacSid;
import org.jaaslounge.decoding.spnego.SpnegoConstants;
import org.jaaslounge.decoding.spnego.SpnegoToken;
import org.jaaslounge.gss.GSSAuthentication;
import org.jaaslounge.ldap.KeepAliveLdapConnection;
import org.jaaslounge.ldap.LdapSidConverter;

public class SpnegoTokenAsserter implements TokenAsserter {
    private static final Logger _LOGGER = SecurityLogger.getLogger();

    /**
     * Vérification de l'identity token
     */
    public IdentityCallbackHandler assertIdentity(String tokenType, IdentityToken token,
            Properties props) throws AsserterException {

        // Vérification du type de token
        if(null == tokenType || 0 == tokenType.length()
                || !"HTTP_REQUEST".equalsIgnoreCase(tokenType))
            throw new AsserterException("Unsupported token type: " + tokenType);
        if(token == null)
            throw new AsserterException("Null token");

        // Récupération des propriétés
        String directoryUrl = props.getProperty(OracleConstants.CONFIG_DIRECTORY_URL);
        String directoryBase = props.getProperty(OracleConstants.CONFIG_DIRECTORY_BASE);
        int directoryTimeout;
        try {
            directoryTimeout = Integer.parseInt(props
                    .getProperty(OracleConstants.CONFIG_DIRECTORY_TIMEOUT));
        } catch(Exception e) {
            directoryTimeout = KeepAliveLdapConnection.DEFAULT_TIMEOUT;
        }
        int ticketMaxSize;
        try {
            ticketMaxSize = Integer.parseInt(props
                    .getProperty(OracleConstants.CONFIG_TICKET_MAX_SIZE));
        } catch(NumberFormatException e) {
            ticketMaxSize = SpnegoToken.TOKEN_MAX_SIZE;
        }

        // Préparation des traitements
        AuthenticatedUser user = null;
        HttpServletRequest request = ((HttpRequestIdentityToken)token).getRequest();
        if(request == null)
            throw new AsserterException("Null request");

        // Traitement du token : Vérification de la présence de l'utilisateur en session
        HttpSession session = request.getSession(false);
        if(session != null) {
            Object attribute = session.getAttribute(AuthenticatedUser.SESSION_ATTRIBUTE_NAME);
            if(attribute != null && attribute instanceof AuthenticatedUser)
                user = (AuthenticatedUser)attribute;
        }

        // Traitement du token : Vérification dans l'en-tête de la requête
        if(user == null) {
            // Lecture de l'en-tête
            byte[] ticket = extractTicket(request.getHeader("Authorization"), ticketMaxSize);

            // Décodage du jeton SPNego
            try {
                SpnegoToken spnegoToken = SpnegoToken.parse(ticket);
                String mechanism = spnegoToken.getMechanism();
                if(SpnegoConstants.KERBEROS_MECHANISM.equals(mechanism)
                        || SpnegoConstants.LEGACY_KERBEROS_MECHANISM.equals(mechanism)) {

                    byte[] mechanismToken = spnegoToken.getMechanismToken();

                    // Authentification du jeton Kerberos
                    System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
                    GSSAuthentication authentication = new GSSAuthentication(mechanismToken);
                    authentication.getUsername();
                    user = new AuthenticatedUser(authentication.getUsername());
                    if(_LOGGER.isLoggable(Level.FINEST)) {
                        _LOGGER.finest("SPNEGO Authentication succeed with user "
                                + authentication.getUsername());
                    }

                    // Décodage du jeton Kerberos et récupération des groupes
                    Security.addProvider(new BouncyCastleProvider());
                    KerberosToken kerberosToken = new KerberosToken(mechanismToken);
                    List<KerberosAuthData> userAuthorizations = kerberosToken.getTicket()
                            .getEncData().getUserAuthorizations();
                    for(KerberosAuthData kerberosAuthData : userAuthorizations) {
                        if(kerberosAuthData instanceof KerberosPacAuthData) {
                            PacLogonInfo logonInfo = ((KerberosPacAuthData)kerberosAuthData)
                                    .getPac().getLogonInfo();

                            List<String> sids = new ArrayList<String>();
                            if(logonInfo.getGroupSid() != null)
                                sids.add(logonInfo.getGroupSid().toString());
                            for(PacSid pacSid : logonInfo.getGroupSids())
                                sids.add(pacSid.toString());
                            for(PacSid pacSid : logonInfo.getExtraSids())
                                sids.add(pacSid.toString());
                            for(PacSid pacSid : logonInfo.getResourceGroupSids())
                                sids.add(pacSid.toString());

                            LdapSidConverter sidConverter = new LdapSidConverter(directoryUrl,
                                    directoryBase, directoryTimeout);
                            List<String> groups = sidConverter.getGroupNames(sids);
                            user = new AuthenticatedUser(logonInfo.getUserName(), logonInfo
                                    .getDomainName(), groups);
                            if(_LOGGER.isLoggable(Level.FINEST)) {
                                _LOGGER.finest("SPNEGO Authentication succeed with user "
                                        + logonInfo.getUserName() + " of realm "
                                        + logonInfo.getDomainName());
                            }
                        }
                    }
                }
            } catch(DecodingException e) {
                if(_LOGGER.isLoggable(Level.FINEST)) {
                    _LOGGER.finest("Token decoding failed.");
                    _LOGGER.finest(e.getMessage());
                }
                throw new AsserterException("SPNEGO Decoding failed.", e);
            } catch(GSSException e) {
                if(_LOGGER.isLoggable(Level.FINEST)) {
                    _LOGGER.finest("GSS Authentication failed.");
                    _LOGGER.finest(e.getMessage());
                }
                throw new AsserterException("GSS Authentication failed.", e);
            } catch(NamingException e) {
                if(_LOGGER.isLoggable(Level.FINEST)) {
                    _LOGGER.finest("LDAP request failed.");
                    _LOGGER.finest(e.getMessage());
                }
                throw new AsserterException("LDAP request failed.", e);
            } catch(Exception e) {
                if(_LOGGER.isLoggable(Level.FINEST)) {
                    _LOGGER.finest("Unexpected error.");
                    _LOGGER.finest(e.getMessage());
                }
                throw new AsserterException("Unexpected error.", e);
            }
        }

        // Vérification du principal
        if(user == null) {
            if(_LOGGER.isLoggable(Level.FINEST))
                _LOGGER.finest("Unable to authentify user: user is null.");
            throw new AsserterException("Unable to authentify user: user is null.");
        }

        // Récupération du nom de l'utilisateur authentifié
        if(_LOGGER.isLoggable(Level.FINEST))
            _LOGGER.finest("User authentified: " + user.getName() + " @ " + user.getDomain());

        // Mise en session de l'utilisateur
        session = request.getSession();
        if(session != null) {
            session.setAttribute(AuthenticatedUser.SESSION_ATTRIBUTE_NAME, user);
        }

        // Création du sujet
        Subject subject = new Subject();
        subject.getPrincipals().add(new UserPrincipal(user.getName()));
        for(String group : user.getGroups())
            subject.getPrincipals().add(new GroupPrincipal(group));

        // Création du callback
        IdentityCallbackHandlerImpl ich = new IdentityCallbackHandlerImpl(user.getName(), subject);
        ich.setAuthenticationType("HTTP_REQUEST");
        ich.setIdentityAsserted(true);

        // Retour du callback
        return ich;
    }

    private byte[] extractTicket(String header, int maxSize) throws AsserterException {
        byte[] ticket = null;

        // Vérification de l'en-tête
        if(header == null || header.trim().length() == 0) {
            if(_LOGGER.isLoggable(Level.FINEST))
                _LOGGER.finest("Unable to find ticket in header.");
            throw new AsserterException("Unable to find ticket in header.");
        }

        // Détermination du type d'authentification proposé par la requête
        if(header.regionMatches(true, 0, "Negotiate ", 0, 10)) {
            if(_LOGGER.isLoggable(Level.FINEST))
                _LOGGER.finest("SPNEGO Authentication proposed, processing...");

            // Extraction du ticket
            int blankIndex = header.indexOf(' ');
            ticket = header.substring(blankIndex).trim().getBytes();

            // Vérification des caractères Base64
            for(int i = 0; i < ticket.length; i++) {
                if(ticket[i] > 122 || (ticket[i] != 43 && ticket[i] < 47)
                        || (ticket[i] > 57 && ticket[i] != 61 && ticket[i] < 65) || (ticket[i] > 90 && ticket[i] < 97))
                    throw new AsserterException("Non-Base64 characters in header.");
            }

            // Décodage du ticket
            ticket = Base64.decode(ticket);
            // Verification de la taille
            if(maxSize > 0 && ticket.length > maxSize)
                throw new AsserterException("Ticket exceeds size limit defined to " + maxSize
                        + " bytes");
        }
        return ticket;
    }
}
