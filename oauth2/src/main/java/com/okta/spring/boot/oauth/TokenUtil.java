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

import com.okta.commons.lang.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

final class TokenUtil {

    private static final Logger log = LoggerFactory.getLogger(TokenUtil.class);
    private static final OAuth2Error INVALID_AUDIENCE = new OAuth2Error(
                        OAuth2ErrorCodes.INVALID_REQUEST,
                        "This aud claim is not equal to the configured audience",
                        "https://tools.ietf.org/html/rfc6750#section-3.1");

    private TokenUtil(){}

    static Collection<? extends GrantedAuthority> tokenScopesToAuthorities(OAuth2AccessToken accessToken) {

        if (accessToken == null || accessToken.getScopes() == null) {
            return Collections.emptySet();
        }

        return accessToken.getScopes().stream()
                .map(scope -> "SCOPE_" + scope)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
    }

    static Collection<? extends GrantedAuthority> tokenClaimsToAuthorities(Map<String, Object> attributes, String claimKey) {

        if (!CollectionUtils.isEmpty(attributes) && StringUtils.hasText(claimKey)) {
            Object rawRoleClaim = attributes.get(claimKey);
            if (rawRoleClaim instanceof Collection) {
                return ((Collection<String>) rawRoleClaim).stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toSet());
            } else if (rawRoleClaim != null) { // don't log when null, that is the default condition
                log.debug("Could not extract authorities from claim '{}', value was not a collection", claimKey);
            }
        }
        return Collections.emptySet();
    }

    static OAuth2TokenValidator<Jwt> jwtValidator(String issuer, String audience ) {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
            validators.add(new JwtTimestampValidator());
            validators.add(new JwtIssuerValidator(issuer));
            validators.add(token -> {
                Set<String> expectedAudience = new HashSet<>();
                expectedAudience.add(audience);
                return !Collections.disjoint(token.getAudience(), expectedAudience)
                        ? OAuth2TokenValidatorResult.success()
                        : OAuth2TokenValidatorResult.failure(INVALID_AUDIENCE);
            });
        return new DelegatingOAuth2TokenValidator<>(validators);
    }

    /**
     * Check if the issuer is root/org URI.
     *
     * Issuer URL that does not follow the pattern '/oauth2/default' (or) '/oauth2/some_id_string' is
     * considered root/org issuer.
     *
     * e.g. https://sample.okta.com (root/org url)
     *      https://sample.okta.com/oauth2/default (non-root issuer/org url)
     *      https://sample.okta.com/oauth2/ausar5cbq5TRRsbcJ0h7 (non-root issuer/org url)
     *
     * @param issuerUri
     * @return true if root/org, false otherwise
     */
    static boolean isRootOrgIssuer(String issuerUri) throws MalformedURLException {
        String uriPath = new URL(issuerUri).getPath();

        if (Strings.hasText(uriPath)) {
            String[] tokenizedUri = uriPath.substring(uriPath.indexOf("/")+1).split("/");

            if (tokenizedUri.length >= 2 &&
                "oauth2".equals(tokenizedUri[0]) &&
                Strings.hasText(tokenizedUri[1])) {
                log.debug("The issuer URL: '{}' is an Okta custom authorization server", issuerUri);
                return false;
            }
        }

        log.debug("The issuer URL: '{}' is an Okta root/org authorization server", issuerUri);
        return true;
    }
}