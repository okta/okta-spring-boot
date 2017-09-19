package com.okta.spring.oauth.code;

import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class ClaimsAuthoritiesExtractor implements AuthoritiesExtractor {

    private final String rolesClaimKey;

    public ClaimsAuthoritiesExtractor(String rolesClaimKey) {
        this.rolesClaimKey = rolesClaimKey;
    }

    @Override
    public List<GrantedAuthority> extractAuthorities(Map<String, Object> map) {
        // extract the string groups from map
        List<String> groups;
        if (map.containsKey(rolesClaimKey)) {
            groups = (List<String>) map.get(rolesClaimKey);
        } else {
            groups = Collections.emptyList();
        }

        // convert them to authorities
        return groups.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}
