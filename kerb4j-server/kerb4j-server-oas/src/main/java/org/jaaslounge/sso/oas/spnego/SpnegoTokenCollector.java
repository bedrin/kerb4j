package org.jaaslounge.sso.oas.spnego;

import java.io.IOException;
import java.util.List;
import java.util.Properties;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import oracle.security.jazn.collector.CollectorException;
import oracle.security.jazn.collector.IdmErrorConstants;
import oracle.security.jazn.collector.oc4j.TokenCollectorImpl;
import oracle.security.jazn.token.HttpRequestIdentityToken;
import oracle.security.jazn.token.IdentityToken;
import oracle.security.jazn.token.TokenNotFoundException;
import oracle.security.jazn.util.SecurityLogger;

import org.jaaslounge.AuthenticatedUser;

/**
 * Collecte et v�rifie la r�cup�ration du token
 * 
 * @author Serli
 * 
 */
public class SpnegoTokenCollector extends TokenCollectorImpl {
    private static final Logger _LOGGER = SecurityLogger.getLogger();

    private boolean retryOnInvalidUser = false;
    private boolean retryOnInsufficientRights = false;

    /**
     * R�cup�ration de l'identity token
     */
    @SuppressWarnings("unchecked")
    public IdentityToken getToken(String tokenType, HttpServletRequest request, List tokenNames,
            Properties properties) throws CollectorException, TokenNotFoundException {

        // R�cup�ration des propri�t�s
        retryOnInvalidUser = Boolean.parseBoolean(properties
                .getProperty(OracleConstants.CONFIG_RETRY_INVALID_USER));
        retryOnInsufficientRights = Boolean.parseBoolean(properties
                .getProperty(OracleConstants.CONFIG_RETRY_INSUFFICIENT_RIGHTS));

        // V�rification du bon type de token
        if(null == tokenType || 0 == tokenType.length()
                || !"HTTP_REQUEST".equalsIgnoreCase(tokenType))
            throw new CollectorException("Unsupported token type: " + tokenType);
        HttpRequestIdentityToken identityToken = (HttpRequestIdentityToken)super.getToken(
                tokenType, request, tokenNames, properties);

        // V�rification en session
        HttpSession session = request.getSession(false);
        if(session != null) {
            Object attribute = session.getAttribute(AuthenticatedUser.SESSION_ATTRIBUTE_NAME);
            if(attribute != null) {
                return identityToken;
            }
        }

        // V�rification dans l'en-t�te de la requ�te
        String ticket = (String)request.getHeader("Authorization");
        if(ticket != null && ticket.startsWith("Negotiate ")) {
            return identityToken;
        }

        // Sinon �chec
        throw new TokenNotFoundException("Unable to find ticket neither in header nor in session.");
    }

    /**
     * Echec de l'authentification
     */
    public void fail(HttpServletRequest request, HttpServletResponse response, int error)
            throws CollectorException {

        _LOGGER.finest("Authentication failed with error code: " + error);

        // R�initialisation de la session
        HttpSession session = request.getSession(false);
        if(session != null)
            session.removeAttribute(AuthenticatedUser.SESSION_ATTRIBUTE_NAME);

        // Cas d'un utilisateur non identifi�
        if(error == IdmErrorConstants.REASON_INVALID_USER) {
            _LOGGER.finest("Authentication failed: invalid credentials.");

            // V�rification de la pr�sence du token
            // au cas o� jazn voudrait tenter un deuxi�me essai
            // alors que nous avons d�j� le ticket
            // ce qui signifierait alors que le ticket est invalide.
            String ticket = (String)request.getHeader("Authorization");
            if(ticket != null && ticket.startsWith("Negotiate ") && !retryOnInvalidUser) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            } else {
                _LOGGER.finest("Retrying authentication...");
                response.addHeader("WWW-Authenticate", "Negotiate");
                response.setHeader("Connection", "close");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
        }

        // Cas d'un utilisateur non autoris�
        else {
            _LOGGER.finest("Authentication failed: insufficient rights.");
            if(!retryOnInsufficientRights) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            } else {
                _LOGGER.finest("Retrying authentication...");
                response.addHeader("WWW-Authenticate", "Negotiate");
                response.setHeader("Connection", "close");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
        }

        try {
            response.flushBuffer();
        } catch(IOException e) {
            _LOGGER.warning("Unable to flush the response.");
        }
    }
}
