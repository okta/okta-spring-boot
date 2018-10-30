package com.okta.spring.boot.oauth;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.HashSet;
import java.util.Set;

final class OktaOAuth2UserService extends DefaultOAuth2UserService {

    private final String groupClaim;

    OktaOAuth2UserService(String groupClaim) {
        this.groupClaim = groupClaim;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {

        OAuth2User user = super.loadUser(userRequest);

        // Only post process requests from the "Okta" reg
        if (!"Okta".equals(userRequest.getClientRegistration().getClientName())) {
            return user;
        }

        // start with authorities from super
        Set<GrantedAuthority> authorities = new HashSet<>(user.getAuthorities());
        // add 'SCOPE_' authorities
        authorities.addAll(TokenUtil.tokenScopesToAuthorities(userRequest.getAccessToken()));
        // add any authorities extracted from the 'group' claim
        authorities.addAll(TokenUtil.tokenClaimsToAuthorities(user.getAttributes(), groupClaim));

        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails()
                .getUserInfoEndpoint().getUserNameAttributeName();

        return new DefaultOAuth2User(authorities, user.getAttributes(), userNameAttributeName);
    }
}