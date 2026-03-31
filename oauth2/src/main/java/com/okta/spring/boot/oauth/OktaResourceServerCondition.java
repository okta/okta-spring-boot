/*
 * Copyright 2022-Present Okta, Inc.
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

import org.springframework.boot.autoconfigure.condition.AnyNestedCondition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.ConfigurationCondition;

/**
 * Activates Okta resource-server auto-configuration when ANY of the following
 * properties is present in the environment:
 *
 * <ol>
 *   <li>{@code okta.oauth2.issuer} – the typical Okta property set by users in
 *       {@code application.properties}. Evaluated at AOT build time so that the
 *       auto-configuration beans are included in native images even when the
 *       OIDC discovery HTTP call cannot be made at build time.</li>
 *   <li>{@code spring.security.oauth2.resourceserver.jwt.issuer-uri} – the
 *       standard Spring Security property; users who opt out of the Okta aliases
 *       and configure Spring Security properties directly should still get Okta's
 *       groups-claim mapping and other enhancements.</li>
 *   <li>{@code spring.security.oauth2.resourceserver.jwt.jwk-set-uri} – the
 *       existing trigger used when the Okta
 *       {@link com.okta.spring.boot.oauth.env.OktaOAuth2PropertiesMappingEnvironmentPostProcessor}
 *       has already mapped the issuer to a JWK set URI (e.g. after a successful
 *       OIDC discovery call at JVM runtime).</li>
 * </ol>
 *
 * <p>Fixes <a href="https://github.com/okta/okta-spring-boot/issues/406">#406</a>:
 * In native images the {@code EnvironmentPostProcessor} may not be able to make
 * the OIDC discovery HTTP call at AOT compile time, so
 * {@code spring.security.oauth2.resourceserver.jwt.jwk-set-uri} is never set in
 * the build-time environment.  Adding {@code okta.oauth2.issuer} as an
 * alternative trigger ensures the beans are included in the native binary; the
 * {@code EnvironmentPostProcessor} then populates all derived Spring Security
 * properties correctly at runtime.</p>
 *
 * @since 3.1.1
 */
class OktaResourceServerCondition extends AnyNestedCondition {

    OktaResourceServerCondition() {
        super(ConfigurationCondition.ConfigurationPhase.REGISTER_BEAN);
    }

    /**
     * Matches when {@code okta.oauth2.issuer} is set – the most common case.
     * This is a static property that is reliably present at AOT build time.
     */
    @ConditionalOnProperty("okta.oauth2.issuer")
    static class OnOktaIssuer {}

    /**
     * Matches when the Spring Security issuer-URI property is set directly,
     * allowing users who prefer Spring Security property names to still benefit
     * from Okta's auto-configuration enhancements.
     */
    @ConditionalOnProperty("spring.security.oauth2.resourceserver.jwt.issuer-uri")
    static class OnSpringIssuerUri {}

    /**
     * Matches when the JWK-set URI is already present – covers the case where
     * the {@code EnvironmentPostProcessor} has already mapped the Okta issuer
     * to the Spring Security JWK-set URI (JVM runtime with successful OIDC
     * discovery, or explicit user configuration).
     */
    @ConditionalOnProperty("spring.security.oauth2.resourceserver.jwt.jwk-set-uri")
    static class OnJwkSetUri {}
}
