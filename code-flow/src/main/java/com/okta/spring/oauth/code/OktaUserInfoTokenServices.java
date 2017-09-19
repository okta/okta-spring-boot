package com.okta.spring.oauth.code;

import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import java.util.Collection;

public class OktaUserInfoTokenServices extends UserInfoTokenServices {

    private final OAuth2ClientContext oauth2ClientContext;

    public OktaUserInfoTokenServices(String userInfoEndpointUrl, String clientId, OAuth2ClientContext oauth2ClientContext) {
        super(userInfoEndpointUrl, clientId);
        this.oauth2ClientContext = oauth2ClientContext;
    }

    @Override
    public OAuth2Authentication loadAuthentication(String accessToken) {

        OAuth2Authentication originalOAuth = super.loadAuthentication(accessToken);
        OAuth2AccessToken existingToken = oauth2ClientContext.getAccessToken();

        CustomOAuth2Request customOAuth2Request = new CustomOAuth2Request(originalOAuth.getOAuth2Request());
        customOAuth2Request.setScope(existingToken.getScope());
        return new OAuth2Authentication(customOAuth2Request, originalOAuth.getUserAuthentication());
    }

    private static class CustomOAuth2Request extends OAuth2Request {

        private CustomOAuth2Request(OAuth2Request other) {
            super(other);
        }

        @Override
        public void setScope(Collection<String> scope) {
            super.setScope(scope);
        }
    }

}
