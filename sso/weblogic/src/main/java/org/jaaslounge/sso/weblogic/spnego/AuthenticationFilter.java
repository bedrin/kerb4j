package org.jaaslounge.sso.weblogic.spnego;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import weblogic.servlet.security.ServletAuthentication;
import weblogic.servlet.security.Utils;

import com.bea.common.security.service.Identity;
import com.bea.common.security.service.NegotiateIdentityAsserterService;
import com.bea.common.security.service.NegotiateIdentityAsserterService.NegotiateIdentityAsserterCallback;

public class AuthenticationFilter implements Filter, NegotiateIdentityAsserterCallback {

	private NegotiateIdentityAsserterService service;

	public AuthenticationFilter(NegotiateIdentityAsserterService niaService) {
		this.service = niaService;
	}

	public void init(FilterConfig filterConfig) throws ServletException {
		service = getService();
	}

	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
			FilterChain filterChain) throws IOException, ServletException {
		service.process(servletRequest, servletResponse, filterChain, this);
	}

	private NegotiateIdentityAsserterService getService() throws ServletException {
		return service;
	}

	public void destroy() {
	}

	public String getWebAppAuthType(HttpServletRequest request) {
		return Utils.getConfiguredAuthMethod(request);
	}

	public boolean isAlreadyAuthenticated() {
		return false;
	}

	public void userAuthenticated(Identity identity, HttpServletRequest request) {
		ServletAuthentication.runAs(identity.getSubject(), request);
	}
}
