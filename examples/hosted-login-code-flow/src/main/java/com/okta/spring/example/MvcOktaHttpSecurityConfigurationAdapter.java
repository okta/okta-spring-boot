package com.okta.spring.example;

import com.okta.spring.oauth.code.OktaHttpSecurityConfigurationAdapter;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.stereotype.Component;

@Order(90)
@Component
public class MvcOktaHttpSecurityConfigurationAdapter extends OktaHttpSecurityConfigurationAdapter {

    @Override
    public void init(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/login").permitAll();
        http.authorizeRequests().antMatchers("/okta/okta.css").permitAll();
    }
}