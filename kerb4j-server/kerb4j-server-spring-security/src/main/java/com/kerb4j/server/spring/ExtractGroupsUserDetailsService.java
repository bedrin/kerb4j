package com.kerb4j.server.spring;

import com.kerb4j.common.marshall.Kerb4JException;
import com.kerb4j.common.marshall.pac.Pac;
import com.kerb4j.common.marshall.pac.PacLogonInfo;
import com.kerb4j.common.marshall.pac.PacSid;
import com.kerb4j.common.marshall.spnego.SpnegoInitToken;
import com.kerb4j.common.marshall.spnego.SpnegoKerberosMechToken;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import javax.security.auth.kerberos.KerberosKey;
import java.util.ArrayList;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ExtractGroupsUserDetailsService implements AuthenticationUserDetailsService<SpnegoAuthenticationToken> {

    @Override
    public UserDetails loadUserDetails(SpnegoAuthenticationToken token) throws UsernameNotFoundException {

        try {
            SpnegoInitToken spnegoInitToken = new SpnegoInitToken(token.getToken());

            SpnegoKerberosMechToken spnegoKerberosMechToken = spnegoInitToken.getSpnegoKerberosMechToken();

            Pac pac = spnegoKerberosMechToken.getPac(new ArrayList<>(token.getSubject().getPrivateCredentials(KerberosKey.class)).toArray(new KerberosKey[3]));

            PacLogonInfo logonInfo = pac.getLogonInfo();

            return new User(token.username(), "N/A",
                    Stream.of(logonInfo.getGroupSids()).map(PacSid::toHumanReadableString).map(SimpleGrantedAuthority::new).collect(Collectors.toList())
            );

        } catch (Kerb4JException | KrbException e) {
            throw new UsernameNotFoundException("Cannot parse Spnego INIT token", e);
        }

    }

}
