/*
 * Copyright 2017 Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.okta.spring.oauth.code.mvc;

import com.okta.spring.oauth.code.OktaOAuthConfig;
import org.springframework.beans.factory.BeanInitializationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.thymeleaf.ThymeleafAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Configuration
@ConditionalOnClass({ThymeleafAutoConfiguration.class})
@ConditionalOnBean({OktaOAuthConfig.class, ThymeleafAutoConfiguration.class})
@EnableConfigurationProperties(OktaWebProperties.class)
public class OktaMvcConfig extends WebMvcConfigurerAdapter {

    @Autowired
    private OktaWebProperties oktaWebProperties;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {

        registry.addInterceptor(oktaLayoutInterceptor());
    }

    @Bean
    protected LoginController loginController() {
        return new LoginController();
    }

    @Bean
    protected MessageSource messageSource() {
        ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();
        messageSource.setBasename(getClass().getPackage().getName().replace('.', '/') +"/i18n");
        return messageSource;
    }

    @Bean
    public HandlerInterceptor oktaLayoutInterceptor() {
        TemplateLayoutInterceptor interceptor = new TemplateLayoutInterceptor();
        interceptor.setHeadViewName(oktaWebProperties.getHead().getView());
        interceptor.setHeadFragmentSelector(oktaWebProperties.getHead().getFragmentSelector());
        interceptor.setLogoUri(oktaWebProperties.getLogo());

        //deal w/ URIs:
        String[] uris = StringUtils.tokenizeToStringArray(oktaWebProperties.getHead().getCssUris(), " \t");
        Set<String> uriSet = new LinkedHashSet<>();
        if (uris != null && uris.length > 0) {
            java.util.Collections.addAll(uriSet, uris);
        }

        uris = StringUtils.tokenizeToStringArray(oktaWebProperties.getHead().getExtraCssUris(), " \t");
        if (uris != null && uris.length > 0) {
            java.util.Collections.addAll(uriSet, uris);
        }

        if (!CollectionUtils.isEmpty(uriSet)) {
            List<String> list = new ArrayList<>();
            list.addAll(uriSet);
            interceptor.setHeadCssUris(list);
        }

        try {
            interceptor.afterPropertiesSet();
        } catch (Exception e) {
            String msg = "Unable to initialize oktaLayoutInterceptor: " + e.getMessage();
            throw new BeanInitializationException(msg, e);
        }

        return interceptor;
    }
}