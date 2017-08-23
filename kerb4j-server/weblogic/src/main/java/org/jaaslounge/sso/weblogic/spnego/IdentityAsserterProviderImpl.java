package org.jaaslounge.sso.weblogic.spnego;

import java.io.Serializable;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import javax.naming.NamingException;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import javax.servlet.Filter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ietf.jgss.GSSException;
import org.jaaslounge.AuthenticatedUser;
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

import weblogic.management.security.ProviderMBean;
import weblogic.security.service.ContextHandler;
import weblogic.security.spi.AuthenticationProviderV2;
import weblogic.security.spi.ChallengeIdentityAsserterV2;
import weblogic.security.spi.IdentityAsserterV2;
import weblogic.security.spi.IdentityAssertionException;
import weblogic.security.spi.PrincipalValidator;
import weblogic.security.spi.ProviderChallengeContext;
import weblogic.security.spi.SecurityServices;
import weblogic.security.spi.ServletAuthenticationFilter;

import com.bea.common.logger.spi.LoggerSpi;
import com.bea.common.security.SecurityLogger;
import com.bea.common.security.internal.utils.negotiate.NegotiateToken;
import com.bea.common.security.jdkutils.ServletAccess;
import com.bea.common.security.jdkutils.ServletInfoSpi;
import com.bea.common.security.legacy.ExtendedSecurityServices;
import com.bea.common.security.service.NegotiateIdentityAsserterService;

public final class IdentityAsserterProviderImpl implements AuthenticationProviderV2,
		ChallengeIdentityAsserterV2, ServletAuthenticationFilter {

	private JaasLoungeIdentityAsserterMBean myMBean;
	private String activeTypes[];
	private String supportedTypes[];
	private String name;
	private String description;
	private String version;
	
	private LoggerSpi _LOGGER;
	private String _LOG_PREFIX;

	public void initialize(ProviderMBean mbean, SecurityServices securityServices) {
		 
		myMBean = (JaasLoungeIdentityAsserterMBean) mbean;
		name = mbean.getName();
		description = myMBean.getDescription();
		version = myMBean.getVersion();
		activeTypes = myMBean.getActiveTypes();
		supportedTypes = myMBean.getSupportedTypes();
		
		// Attaching to the SecurityAtn logger 
		//  -Dweblogic.debug.DebugSecurityAtn=true 
		//  -Dweblogic.StdoutDebugEnabled=false
		ExtendedSecurityServices services = (ExtendedSecurityServices) securityServices;
		_LOGGER = services.getLogger("SecurityAtn");
		_LOG_PREFIX = name + " - ";
		
		if(_LOGGER.isDebugEnabled()) {
			_LOGGER.debug(_LOG_PREFIX + "Initializing " + name);
			_LOGGER.debug(_LOG_PREFIX + "\tDescription:" + description);
			_LOGGER.debug(_LOG_PREFIX + "\tVersion:" + version);
			_LOGGER.debug(_LOG_PREFIX + "\tActive Types:" + Arrays.toString(activeTypes));
			_LOGGER.debug(_LOG_PREFIX + "\tSupported Types:" + Arrays.toString(supportedTypes));
		}

		// AuthenticationSecurityHelper securityHelper = AuthenticationSecurityHelper.getInstance(mbean);
		// securityHelper.setExtendedSecurityServices(services);
		// Mhh we cannot do that here, securityHelper.getIAServiceLogger is
		// package-protected :(
		// log = securityHelper.getIAServiceLogger();

	}

	public String getDescription() {
		return description;
	}

	public void shutdown() {
		if(_LOGGER.isDebugEnabled()) {
			_LOGGER.debug(_LOG_PREFIX + "Shutting down " + name);
		}
	}

	public IdentityAsserterV2 getIdentityAsserter() {
		// This is an IdentityAsserterV2
		return this;
	}

	public CallbackHandler assertIdentity(String tokenType, Object token, ContextHandler context)
			throws IdentityAssertionException {
		ProviderChallengeContext ctx = assertChallengeIdentity(tokenType, token, null);
		if (ctx == null || !ctx.hasChallengeIdentityCompleted())
			throw new IdentityAssertionException(SecurityLogger.getChallengeNotCompleted());
		else
			return ctx.getCallbackHandler();

	}

	public AppConfigurationEntry getLoginModuleConfiguration() {
		// We don't need that, only for pure Authentication Provider
		return null;
	}

	public AppConfigurationEntry getAssertionModuleConfiguration() {
		return new AppConfigurationEntry(
				"org.jaaslounge.sso.weblogic.spnego.LoginModuleImpl",
				LoginModuleControlFlag.REQUIRED, new HashMap<String, String>());
	}

	// PrincipalValidatorImpl is deprecated however the correct validator
	// com.bea.common.security.provider.PrincipalValidatorImpl
	// doesn't have a default contructor yet
	@SuppressWarnings("deprecation")
	public PrincipalValidator getPrincipalValidator() {
		return new weblogic.security.provider.PrincipalValidatorImpl();
	}

	public ProviderChallengeContext assertChallengeIdentity(String tokenType, Object token,
			ContextHandler handler) throws IdentityAssertionException {

		if (tokenType == null) {
			throw new IdentityAssertionException(SecurityLogger.getIATypeCanNotBeNull());
		}
		if (token == null) {
			throw new IdentityAssertionException(SecurityLogger.getIATokenCanNotBeNull());
		}

        // R�cup�ration des propri�t�s
        String directoryUrl = System.getProperty(WeblogicConstants.CONFIG_DIRECTORY_URL);
        String directoryBase = System.getProperty(WeblogicConstants.CONFIG_DIRECTORY_BASE);
        int directoryTimeout;
        try {
            directoryTimeout = Integer.parseInt(System
                    .getProperty(WeblogicConstants.CONFIG_DIRECTORY_TIMEOUT));
        } catch(Exception e) {
            directoryTimeout = KeepAliveLdapConnection.DEFAULT_TIMEOUT;
        }
        int ticketMaxSize;
        try {
            ticketMaxSize = Integer.parseInt(System
                    .getProperty(WeblogicConstants.CONFIG_TICKET_MAX_SIZE));
        } catch(NumberFormatException e) {
            ticketMaxSize = SpnegoToken.TOKEN_MAX_SIZE;
        }
        
		NegotiateToken nToken = (NegotiateToken) token;
		if(!nToken.getTokenTypeName().equals(NegotiateToken.TOKEN_NAME_SPNEGO)) {
			throw new IdentityAssertionException("The token type isn't correct, it should be '" + NegotiateToken.TOKEN_NAME_SPNEGO + "'");
		}
		
        // V�rification de la taille
        if(ticketMaxSize > 0 && nToken.getRawBytes().length > ticketMaxSize)
            throw new IdentityAssertionException("Ticket exceeds size limit defined to " + ticketMaxSize
                    + " bytes");

        AuthenticatedUser user = null;
        
		// D�codage du jeton SPNego
		try {
			
			SpnegoToken spnegoToken = SpnegoToken.parse(nToken.getRawBytes());
			String mechanism = spnegoToken.getMechanism();

			if (SpnegoConstants.KERBEROS_MECHANISM.equals(mechanism)
					|| SpnegoConstants.LEGACY_KERBEROS_MECHANISM.equals(mechanism)) {
				
				byte[] mechanismToken = spnegoToken.getMechanismToken();

				// Authentification du jeton Kerberos
				System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
				GSSAuthentication authentication = new GSSAuthentication(mechanismToken);
				user = new AuthenticatedUser(authentication.getUsername());
				if(_LOGGER.isDebugEnabled()) {
					_LOGGER.debug(_LOG_PREFIX + "SPNEGO Authentication succeed with user "
						+ authentication.getUsername());
				}

                // D�codage du jeton Kerberos et r�cup�ration des groupes
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
        				if(_LOGGER.isDebugEnabled()) {
        					_LOGGER.debug("SPNEGO Authentication succeed with user "
                                    + logonInfo.getUserName() + " of realm "
                                    + logonInfo.getDomainName());
        				}
                    }
                }
				
			}

		} catch (DecodingException e) {
			if(_LOGGER.isDebugEnabled()) {
				_LOGGER.debug(_LOG_PREFIX + "SPNEGO Decoding failed");
				_LOGGER.debug(_LOG_PREFIX + e.getMessage());
			}
			throw new IdentityAssertionException("SPNEGO Decoding failed." + e.getMessage());
		} catch (GSSException e) {
			if(_LOGGER.isDebugEnabled()) {
				_LOGGER.debug(_LOG_PREFIX + "GSS Authentication failed.");
				_LOGGER.debug(_LOG_PREFIX + e.getMessage());
			}
			throw new IdentityAssertionException("GSS Authentication failed." + e.getMessage());
		} catch (NamingException e) {
			if(_LOGGER.isDebugEnabled()) {
				_LOGGER.debug(_LOG_PREFIX + "LDAP request failed.");
				_LOGGER.debug(_LOG_PREFIX + e.getMessage());
			}
			throw new IdentityAssertionException("LDAP request failed." + e.getMessage());
		}

        // V�rification du principal
        if(user == null) {
        	if(_LOGGER.isDebugEnabled()) {
        		_LOGGER.debug(_LOG_PREFIX + "Unable to authentify user: user is null.");
        	}
            throw new IdentityAssertionException("Unable to authentify user: user is null.");
        }
        
        if(_LOGGER.isDebugEnabled()) {
        	_LOGGER.debug(_LOG_PREFIX + "User authentified: " + user.getName() + " @ " + user.getDomain()
        			+ " with groups " + Arrays.toString(user.getGroups().toArray(new String[user.getGroups().size()])));
        }
        
		ProviderChallengeContext ctx = new ProviderChallengeContextImpl(
				new CallbackHandlerImpl(user.getName(), user.getGroups())); 
		return ctx;
	}

	public void continueChallengeIdentity(ProviderChallengeContext context, String tokenType,
			Object token, ContextHandler handler) throws IdentityAssertionException {
		// No more challenges
	}

	public Object getChallengeToken(String type, ContextHandler handler) {
		// Returns a response with a WWW-Authenticate Negotiate header
		return weblogic.security.spi.IdentityAsserter.WWW_AUTHENTICATE_NEGOTIATE;
	}

	private class ProviderChallengeContextImpl implements ProviderChallengeContext, Serializable {

		private static final long serialVersionUID = 1L;
		private CallbackHandler handler;

		public ProviderChallengeContextImpl(CallbackHandler handler) {
			super();
			setCallbackHandler(handler);
		}

		public CallbackHandler getCallbackHandler() {
			return handler;
		}

		public Object getChallengeToken() {
			return null;
		}

		public boolean hasChallengeIdentityCompleted() {
			return handler != null;
		}

		protected void setCallbackHandler(CallbackHandler handler) {
			this.handler = handler;
		}

	}

	public Filter[] getServletAuthenticationFilters() {

		boolean correctSetUp = true;
		for (String supportedType : supportedTypes) {
			boolean isActive = false;
			for (String activeType : activeTypes) {
				if (supportedType.equals(activeType)) {
					isActive = true;
				}
			}
			correctSetUp = correctSetUp && isActive;
		}

		if (!correctSetUp) {
	        if(_LOGGER.isDebugEnabled()) {
	        	_LOGGER.debug(_LOG_PREFIX + "Required active types are not present, negociate filter will not be able to assert identities");
	        }
			return new Filter[0];
		}

        if(_LOGGER.isDebugEnabled()) {
        	_LOGGER.debug(_LOG_PREFIX + "Initializing AuthenticationFilter");
        }
		
		
		Filter filters[] = new Filter[1];
		ServletInfoSpi servletInfo = ServletAccess.getInstance().getServletInfo(
				myMBean.getRealm().getName());
		NegotiateIdentityAsserterService identityAsserterService = (NegotiateIdentityAsserterService) servletInfo
				.getNegotiateFilterService();
		AuthenticationFilter negotiateFilter = new AuthenticationFilter(identityAsserterService);
		filters[0] = negotiateFilter;
		return filters;
	}

}
