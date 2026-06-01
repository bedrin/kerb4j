package com.kerb4j.server.spring.docs;

import com.kerb4j.server.spring.KerberosAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.web.SecurityFilterChain;

//tag::snippetA[]
@Configuration
@EnableWebSecurity
public class AuthProviderConfig {

    @Bean
    public SecurityFilterChain configure(final HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(a ->
                        a.requestMatchers("/", "/home").permitAll()
                                .anyRequest().authenticated())
                .formLogin(l -> l.loginPage("/login").permitAll())
                .logout(LogoutConfigurer::permitAll)
                .build();
    }

    @Bean
    protected AuthenticationManager authManager(final HttpSecurity http) throws Exception {
        return http
                .getSharedObject(AuthenticationManagerBuilder.class)
                .authenticationProvider(kerberosAuthenticationProvider())
                .build();
    }

    @Bean
    public KerberosAuthenticationProvider kerberosAuthenticationProvider() {
        final KerberosAuthenticationProvider provider = new KerberosAuthenticationProvider();
        provider.setUserDetailsService(dummyUserDetailsService());
        return provider;
    }

    @Bean
    public DummyUserDetailsService dummyUserDetailsService() {
        return new DummyUserDetailsService();
    }

}
//end::snippetA[]
