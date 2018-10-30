package com.okta.spring.boot.oauth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

final class TokenUtil {

    private static final Logger log = LoggerFactory.getLogger(TokenUtil.class);

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
}
