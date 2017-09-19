package com.okta.spring.oauth.code;

import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor;

import java.util.Map;

public class ClaimsPrincipalExtractor implements PrincipalExtractor {

    private final String principalClaimKey;

    public ClaimsPrincipalExtractor(String principalClaimKey) {
        this.principalClaimKey = principalClaimKey;
    }

    @Override
    public Object extractPrincipal(Map<String, Object> map) {
        return map.get(principalClaimKey);
    }
}
