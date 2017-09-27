package com.okta.spring.oauth.code;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import java.util.List;

public class OktaWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    @Autowired
    private List<OktaHttpSecurityConfigurationAdapter> securityConfigurationAdapters;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        securityConfigurationAdapters.forEach(a -> {
            try {
                http.apply(a);
            } catch (Exception e) {
                throw new InvalidConfigurationException("Failed to apply OktaHttpSecurityConfigurationAdapter.", e);
            }
        });
    }
}