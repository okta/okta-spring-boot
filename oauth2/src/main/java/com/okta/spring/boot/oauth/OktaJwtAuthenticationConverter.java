package com.okta.spring.boot.oauth;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import java.util.Collection;
import java.util.HashSet;

final class OktaJwtAuthenticationConverter extends JwtAuthenticationConverter {

    private final String groupClaim;

    public OktaJwtAuthenticationConverter(String groupClaim) {
        this.groupClaim = groupClaim;
    }

    @Override
    protected Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {

        Collection<GrantedAuthority> result = new HashSet<>(super.extractAuthorities(jwt));
        result.addAll(TokenUtil.tokenClaimsToAuthorities(jwt.getClaims(), groupClaim));

        return result;
    }
}
