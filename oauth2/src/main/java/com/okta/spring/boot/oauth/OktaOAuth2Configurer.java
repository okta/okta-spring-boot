/*
 * Copyright 2018-Present Okta, Inc.
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
package com.okta.spring.boot.oauth;

import com.okta.spring.boot.oauth.config.OktaOAuth2Properties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;

import java.lang.reflect.Field;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Optional;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import static com.okta.commons.lang.Strings.isEmpty;

final class OktaOAuth2Configurer extends AbstractHttpConfigurer<OktaOAuth2Configurer, HttpSecurity> {

    private static final Logger log = LoggerFactory.getLogger(OktaOAuth2Configurer.class);

    @SuppressWarnings("rawtypes")
    @Override
    public void init(HttpSecurity http) {

        ApplicationContext context = http.getSharedObject(ApplicationContext.class);

        // make sure OktaOAuth2Properties are available
        if (!context.getBeansOfType(OktaOAuth2Properties.class).isEmpty()) {
            OktaOAuth2Properties oktaOAuth2Properties = context.getBean(OktaOAuth2Properties.class);

            // Auth Code Flow Config
            try {
                initializeOAuth2ClientConfiguration(http, context, oktaOAuth2Properties);
            } catch (ClassNotFoundException e) {
                log.warn("OAuth2ClientProperties not found on classpath. Ensure spring-boot-starter-security-oauth2-client is included as a dependency.", e);
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize OAuth2 client configuration", e);
            }
        }
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private void initializeOAuth2ClientConfiguration(HttpSecurity http, ApplicationContext context, OktaOAuth2Properties oktaOAuth2Properties) throws Exception {
        // Load class dynamically to support Spring Boot 3.x and 4.x
        // Try Spring Boot 4.x package first, then fall back to Spring Boot 3.x package.
        // The class moved from org.springframework.boot.autoconfigure.security.oauth2.client
        // to org.springframework.boot.security.oauth2.client.autoconfigure in Spring Boot 4.x.
        Class<?> oauth2ClientPropertiesClass;
        try {
            oauth2ClientPropertiesClass = Class.forName("org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientProperties");
        } catch (ClassNotFoundException e4) {
            oauth2ClientPropertiesClass = Class.forName("org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties");
        }
        
        // Check if bean exists
        java.util.Map<String, ?> beans = context.getBeansOfType(oauth2ClientPropertiesClass);
        if (beans.isEmpty()) {
            log.debug("OAuth2ClientProperties bean not found in context. Skipping OAuth2 client configuration.");
            return;
        }

        Object clientPropertiesBean = beans.values().iterator().next();
        
        // Get provider and registration using reflection
        java.lang.reflect.Method getProviderMethod = oauth2ClientPropertiesClass.getMethod("getProvider");
        java.lang.reflect.Method getRegistrationMethod = oauth2ClientPropertiesClass.getMethod("getRegistration");
        
        java.util.Map<String, ?> providers = (java.util.Map<String, ?>) getProviderMethod.invoke(clientPropertiesBean);
        java.util.Map<String, ?> registrations = (java.util.Map<String, ?>) getRegistrationMethod.invoke(clientPropertiesBean);
        
        Object okataProvider = providers != null ? providers.get("okta") : null;
        Object oktaRegistration = registrations != null ? registrations.get("okta") : null;
        
        if (okataProvider != null && oktaRegistration != null) {
            // Extract issuer URI and client ID using reflection
            java.lang.reflect.Method getIssuerUriMethod = okataProvider.getClass().getMethod("getIssuerUri");
            String issuerUri = (String) getIssuerUriMethod.invoke(okataProvider);
            
            java.lang.reflect.Method getClientIdMethod = oktaRegistration.getClass().getMethod("getClientId");
            String clientId = (String) getClientIdMethod.invoke(oktaRegistration);
            
            if (!isEmpty(issuerUri) && !isEmpty(clientId)) {
                // configure Okta user services
                configureLogin(http, context.getEnvironment());

                // check for RP-Initiated logout
                if (!context.getBeansOfType(OidcClientInitiatedLogoutSuccessHandler.class).isEmpty()) {
                    OidcClientInitiatedLogoutSuccessHandler handler = context.getBean(OidcClientInitiatedLogoutSuccessHandler.class);
                    http.logout(logout -> logout.logoutSuccessHandler(handler));
                }

                // Check if OAuth2ResourceServerConfigurer is already configured. If it is, skip opaque token configuration.
                OAuth2ResourceServerConfigurer<HttpSecurity> authenticationManagerResolver = http.getConfigurer(OAuth2ResourceServerConfigurer.class);
                if (authenticationManagerResolver != null) {
                    log.debug("AuthenticationManagerResolver is already configured. Skipping opaque token configuration.");
                    return;
                }

                // Resource Server Config
                OAuth2ResourceServerProperties.Opaquetoken propertiesOpaquetoken;
                try {
                    if (!context.getBeansOfType(OAuth2ResourceServerProperties.class).isEmpty()
                        && (propertiesOpaquetoken = context.getBean(OAuth2ResourceServerProperties.class).getOpaquetoken()) != null
                        && !isEmpty(propertiesOpaquetoken.getIntrospectionUri())
                        && TokenUtil.isRootOrgIssuer(issuerUri)) {
                        log.debug("Opaque Token validation/introspection will be configured.");
                        configureResourceServerForOpaqueTokenValidation(http, oktaOAuth2Properties);
                        return;
                    }
                    OAuth2ResourceServerConfigurer oAuth2ResourceServerConfigurer = http.getConfigurer(OAuth2ResourceServerConfigurer.class);

                    if (getJwtConfigurer(oAuth2ResourceServerConfigurer).isPresent()) {
                        log.debug("JWT configurer is set in OAuth resource server configuration. " +
                            "JWT validation will be configured.");
                        configureResourceServerForJwtValidation(http, oktaOAuth2Properties);
                    } else if (getOpaqueTokenConfigurer(oAuth2ResourceServerConfigurer).isPresent()) {
                        log.debug("Opaque Token configurer is set in OAuth resource server configuration. " +
                            "Opaque Token validation/introspection will be configured.");
                        configureResourceServerForOpaqueTokenValidation(http, oktaOAuth2Properties);
                    } else {
                        log.debug("OAuth2ResourceServerConfigurer bean not configured, Resource Server support will not be enabled.");
                    }
                } catch (Exception e) {
                    throw new RuntimeException("Failed to configure OAuth2 resource server", e);
                }
            } else {
                log.debug("OAuth/OIDC Login not configured due to missing issuer, client-id, or client-secret property");
            }
        } else {
            log.debug("OAuth/OIDC Login not configured due to missing okta provider or registration configuration");
        }
    }

    private Optional<OAuth2ResourceServerConfigurer<?>.JwtConfigurer> getJwtConfigurer(OAuth2ResourceServerConfigurer<?> oAuth2ResourceServerConfigurer) throws IllegalAccessException {
        if (oAuth2ResourceServerConfigurer != null) {
            return getFieldValue(oAuth2ResourceServerConfigurer, "jwtConfigurer");
        }
        return Optional.empty();
    }

    private Optional<OAuth2ResourceServerConfigurer<?>.OpaqueTokenConfigurer> getOpaqueTokenConfigurer(OAuth2ResourceServerConfigurer<?> oAuth2ResourceServerConfigurer) throws IllegalAccessException {
        if (oAuth2ResourceServerConfigurer != null) {
            return getFieldValue(oAuth2ResourceServerConfigurer, "opaqueTokenConfigurer");
        }
        return Optional.empty();
    }

    private <T> Optional<T> getFieldValue(Object source, String fieldName) throws IllegalAccessException {
        Field field = AccessController.doPrivileged((PrivilegedAction<Field>) () -> {
            Field result = null;
            try {
                result = OAuth2ResourceServerConfigurer.class.getDeclaredField(fieldName);
                result.setAccessible(true);
            } catch (NoSuchFieldException e) {
                log.warn("Could not get field '" + fieldName + "' of {} via reflection",
                    OAuth2ResourceServerConfigurer.class.getName(), e);
            }
            return result;
        });

        if (field == null) {
            String errMsg = "Expected field '" + fieldName + "' was not found in OAuth resource server configuration. " +
                "Version incompatibility with Spring Security detected." +
                "Check https://github.com/okta/okta-spring-boot for project updates.";
            throw new RuntimeException(errMsg);
        }

        return Optional.ofNullable((T) field.get(source));
    }

    /**
     * Method to "unset" Jwt Resource Server Configurer using Reflection API.
     * <p>
     * For Root/Org issuer cases, we automatically configure resource server to use Opaque Token validation mode, but Spring
     * brings in the default Jwt configuration, therefore we are unable to set Opaque Token configuration
     * programmatically (startup fails - Spring only supports Jwt or Opaque is supported, not both simultaneously).
     * To address this, we need this helper method to unset Jwt configurer before attempting to set Opaque Token configuration
     * for Root/Org issuer use case.
     */
    @SuppressWarnings("PMD.UnusedPrivateMethod")
    private void unsetJwtConfigurer(OAuth2ResourceServerConfigurer oAuth2ResourceServerConfigurer) {

        AccessController.doPrivileged((PrivilegedAction<Field>) () -> {
            Field result = null;
            try {
                result = OAuth2ResourceServerConfigurer.class.getDeclaredField("jwtConfigurer");
                result.setAccessible(true);

                result.set(oAuth2ResourceServerConfigurer, null);
            } catch (NoSuchFieldException | IllegalAccessException e) {
                log.warn("Could not access field '" + "jwtConfigurer" + "' of {} via reflection",
                    OAuth2ResourceServerConfigurer.class.getName(), e);
            }
            return result;
        });
    }

    private void configureLogin(HttpSecurity http, Environment environment) {

        String redirectUriProperty = environment.getProperty("spring.security.oauth2.client.registration.okta.redirect-uri");
        String redirectUri = redirectUriProperty != null ? redirectUriProperty.replace("{baseUrl}", "") : null;

        http.oauth2Login(oauth2Login -> {
            oauth2Login.tokenEndpoint(tokenEndpoint -> tokenEndpoint
                .accessTokenResponseClient(accessTokenResponseClient()));
            if (redirectUri != null) {
                oauth2Login.redirectionEndpoint(redirectionEndpoint -> redirectionEndpoint.baseUri(redirectUri));
            }
        });
    }

    private void configureResourceServerForJwtValidation(HttpSecurity http, OktaOAuth2Properties oktaOAuth2Properties) {
        // Do not override if user has already set a custom converter directly in their DSL
        // (init() runs during http.build(), so user's DSL settings are already applied)
        if (hasUserSetJwtAuthenticationConverter(http)) {
            log.debug("Custom jwtAuthenticationConverter detected in DSL - Okta will not override it.");
            return;
        }

        ApplicationContext context = http.getSharedObject(ApplicationContext.class);

        // Check for a user-provided custom JwtAuthenticationConverter bean.
        // OktaOAuth2ResourceServerAutoConfig registers OktaJwtAuthenticationConverter with
        // @ConditionalOnMissingBean, so if user provided their own bean, Okta's won't be registered.
        Optional<JwtAuthenticationConverter> customConverterBean = context
            .getBeansOfType(JwtAuthenticationConverter.class)
            .values().stream()
            .filter(c -> !(c instanceof OktaJwtAuthenticationConverter))
            .findFirst();

        if (customConverterBean.isPresent()) {
            log.debug("Custom JwtAuthenticationConverter bean found - using it instead of Okta's default.");
            JwtAuthenticationConverter converter = customConverterBean.get();
            http.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(converter)));
            return;
        }

        // Default: use the OktaJwtAuthenticationConverter bean already registered in the context,
        // which has AuthoritiesProvider beans injected by OktaOAuth2ResourceServerAutoConfig
        // (fix for #160: AuthoritiesProvider not being used in resource server JWT flows).
        // Fall back to a bare instance only when the bean is unavailable (e.g. resource-server-only
        // setup without the JWK-set URI so the @ConditionalOnMissingBean bean wasn't created).
        JwtAuthenticationConverter oktaConverter = context.getBeansOfType(JwtAuthenticationConverter.class)
            .values().stream()
            .filter(c -> c instanceof OktaJwtAuthenticationConverter)
            .findFirst()
            .orElseGet(() -> new OktaJwtAuthenticationConverter(oktaOAuth2Properties));
        http.oauth2ResourceServer(oauth2 -> oauth2
            .jwt(jwt -> jwt.jwtAuthenticationConverter(oktaConverter)));
    }

    /**
     * Checks via reflection whether the user has already explicitly set a
     * {@code jwtAuthenticationConverter} on the {@link OAuth2ResourceServerConfigurer.JwtConfigurer}.
     * Returns {@code true} if a non-null converter was set in the user's DSL before
     * {@code init()} ran, so Okta should not override it.
     */
    private boolean hasUserSetJwtAuthenticationConverter(HttpSecurity http) {
        return AccessController.doPrivileged((PrivilegedAction<Boolean>) () -> {
            try {
                OAuth2ResourceServerConfigurer<?> rsConfigurer =
                    http.getConfigurer(OAuth2ResourceServerConfigurer.class);
                if (rsConfigurer == null) return false;

                Object jwtConfigurer;
                try {
                    jwtConfigurer = getJwtConfigurer(rsConfigurer).orElse(null);
                } catch (IllegalAccessException e) {
                    return false;
                }
                if (jwtConfigurer == null) return false;

                // Walk the class hierarchy of the inner JwtConfigurer to find the field
                Class<?> clazz = jwtConfigurer.getClass();
                while (clazz != null && clazz != Object.class) {
                    try {
                        Field field = clazz.getDeclaredField("jwtAuthenticationConverter");
                        field.setAccessible(true);
                        return field.get(jwtConfigurer) != null;
                    } catch (NoSuchFieldException e) {
                        clazz = clazz.getSuperclass();
                    } catch (IllegalAccessException e) {
                        log.debug("Cannot read jwtAuthenticationConverter field.", e);
                        return false;
                    }
                }
            } catch (Exception e) {
                log.debug("Could not inspect JwtConfigurer for existing converter. Proceeding with Okta default.", e);
            }
            return false;
        });
    }

    private void configureResourceServerForOpaqueTokenValidation(HttpSecurity http, OktaOAuth2Properties oktaOAuth2Properties) {

        if (!isEmpty(oktaOAuth2Properties.getClientId()) && !isEmpty(oktaOAuth2Properties.getClientSecret())) {
            // Spring (2.7.x+) configures JWT be default and this creates startup failure "Spring Security
            // only supports JWTs or Opaque Tokens, not both at the same time" when we try to configure Opaque Token mode in following line.
            // Therefore, we are unsetting JWT mode before attempting to configure Opaque Token mode for ROOT issuer case.

            if (http.getConfigurer(OAuth2ResourceServerConfigurer.class) != null) {
                unsetJwtConfigurer(http.getConfigurer(OAuth2ResourceServerConfigurer.class));
            }

            http.oauth2ResourceServer(oauth2 -> oauth2.opaqueToken(org.springframework.security.config.Customizer.withDefaults()));
        }
    }

    private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
        // Spring Security 7.x uses RestClientAuthorizationCodeTokenResponseClient
        // which is based on RestClient. For now, we use the default implementation.
        // Custom RestTemplate configuration can be applied via RestClient.builder()
        return new RestClientAuthorizationCodeTokenResponseClient();
    }
}
