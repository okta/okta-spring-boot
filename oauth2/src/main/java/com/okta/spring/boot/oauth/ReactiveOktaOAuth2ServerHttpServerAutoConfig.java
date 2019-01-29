/*
 * Copyright 2012-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.okta.spring.boot.oauth;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.DelegatingReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.util.ClassUtils;
import org.springframework.web.bind.annotation.ResponseStatus;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Configuration
@AutoConfigureAfter(ReactiveOktaOAuth2AutoConfig.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@ConditionalOnClass({ Flux.class, EnableWebFluxSecurity.class, ClientRegistration.class })
@ConditionalOnBean(ReactiveOktaOAuth2AutoConfig.class)
class ReactiveOktaOAuth2ServerHttpServerAutoConfig {

    @Bean
    BeanPostProcessor authManagerServerHttpSecurityBeanPostProcessor(@Qualifier("oauth2UserService") ReactiveOAuth2UserService oAuth2UserService,
                                                                     @Qualifier("oidcUserService") OidcReactiveOAuth2UserService oidcUserService) {
        return new OktaOAuth2LoginServerBeanPostProcessor(oAuth2UserService, oidcUserService);
    }

    /*
     * Fix for https://github.com/spring-projects/spring-security/issues/6484
     */
    private static ReactiveAuthenticationManager reactiveAuthenticationManager(ReactiveOAuth2UserService oAuth2UserService,
                                                                               OidcReactiveOAuth2UserService oidcUserService) {
        WebClientReactiveAuthorizationCodeTokenResponseClient client = new WebClientReactiveAuthorizationCodeTokenResponseClient();
        ReactiveAuthenticationManager result = new OAuth2LoginReactiveAuthenticationManager(client, oAuth2UserService) {
            @Override
            public Mono<Authentication> authenticate(Authentication authentication) {
                return wrapOnErrorMap(super.authenticate(authentication));
            }
        };

        boolean oidcAuthenticationProviderEnabled = ClassUtils.isPresent(
                "org.springframework.security.oauth2.jwt.JwtDecoder", ReactiveOktaOAuth2ServerHttpServerAutoConfig.class.getClassLoader());
        if (oidcAuthenticationProviderEnabled) {
            OidcAuthorizationCodeReactiveAuthenticationManager oidc = new OidcAuthorizationCodeReactiveAuthenticationManager(client, oidcUserService) {
                @Override
                public Mono<Authentication> authenticate(Authentication authentication) {
                    return wrapOnErrorMap(super.authenticate(authentication));
                }
            };
            result = new DelegatingReactiveAuthenticationManager(oidc, result);
        }
        return result;
    }

    private static Mono<Authentication> wrapOnErrorMap(Mono<Authentication> authentication) {
        return authentication.onErrorMap(ReactiveOktaOAuth2ServerHttpServerAutoConfig::shouldWrapException,
                                         e -> new UnknownOAuthException("An error occurred while attempting to authenticate: ", e));
    }

    private static boolean shouldWrapException(Throwable e) {
        return e instanceof IllegalStateException
            || e instanceof JwtException
            || e instanceof AuthenticationException;
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    static class UnknownOAuthException extends AuthenticationException {
        UnknownOAuthException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    static class OktaOAuth2LoginServerBeanPostProcessor implements BeanPostProcessor {

        private final ReactiveOAuth2UserService oAuth2UserService;
        private final OidcReactiveOAuth2UserService oidcUserService;

        OktaOAuth2LoginServerBeanPostProcessor(ReactiveOAuth2UserService oAuth2UserService, OidcReactiveOAuth2UserService oidcUserService) {
            this.oAuth2UserService = oAuth2UserService;
            this.oidcUserService = oidcUserService;
        }

        @Override
        public Object postProcessAfterInitialization(Object bean, String beanName) {
            if (bean instanceof ServerHttpSecurity) {
                ((ServerHttpSecurity) bean).oauth2Login().authenticationManager(reactiveAuthenticationManager(oAuth2UserService, oidcUserService));
            }
            return bean;
        }
    }
}