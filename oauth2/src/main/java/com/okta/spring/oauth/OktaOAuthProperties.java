/*
 * Copyright 2017 Okta, Inc.
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
package com.okta.spring.oauth;

import org.springframework.boot.context.properties.ConfigurationProperties;

import javax.annotation.PostConstruct;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@ConfigurationProperties("okta")
public class OktaOAuthProperties {


    private ClientProperties client = new ClientProperties();

    private OAuthProperties oauth2 = new OAuthProperties();

    private Map<String, Object> extraWidgetConfig = new HashMap<>();


    @PostConstruct
    public void init() {
        // make sure 'features' is a map
        Object[] idps = convertToArray(extraWidgetConfig.get("idps"));
        if (idps.length > 0) {
            extraWidgetConfig.put("idps", idps);
        }
    }

    private Object[] convertToArray(Object array) {
        if (array instanceof Map) {
            Map map = (Map) array;
            return map.values().toArray();
        }
        return new Object[0];
    }

    public ClientProperties getClient() {
        return client;
    }

    public void setClient(ClientProperties client) {
        this.client = client;
    }


    public OAuthProperties getOauth2() {
        return oauth2;
    }

    public void setOauth2(OAuthProperties oauth2) {
        this.oauth2 = oauth2;
    }

    public Map<String, Object> getExtraWidgetConfig() {
        return extraWidgetConfig;
    }

    public void setExtraWidgetConfig(Map<String, Object> extraWidgetConfig) {
        this.extraWidgetConfig = extraWidgetConfig;
    }

    public static class ClientProperties {
        private String orgUrl;

        public String getOrgUrl() {
            return orgUrl;
        }

        public void setOrgUrl(String orgUrl) {
            this.orgUrl = orgUrl;
        }
    }

    public static class OAuthProperties {

        /**
         * Login route path.
         */
        private String redirectUri = "/login";

        /**
         * Custom login page hosted by this application.
         */
        private String customLoginRoute;

        /**
         *  OAuth2 clientId value.
         */
        private String clientId;

        /**
         * OAuth2 client secret value.
         */
        private String clientSecret;

        /**
         * OIDC discovery URL, when set all properties that are discoverable will be populated automatically.
         */
        private String discoveryUri;

        /**
         * Custom authorization server issuer URL: i.e. 'https://dev-123456.oktapreview.com/oauth2/ausar5cbq5TRooicu812'.
         */
        private String issuer;

        /**
         * Expected access token audience claim value.
         */
        private String audience = "api://default";

        /**
         * Access token scope claim key.
         */
        private String scopeClaim = "scp";

        /**
         * Access token roles/groups claim key.
         */
        private String rolesClaim = "groups";

        private List<String> scopes = Arrays.asList("openid", "profile", "email");

        /**
         * Claim to pull the principal name from.
         */
        private String principalClaim = "email";

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public String getAudience() {
            return audience;
        }

        public void setAudience(String audience) {
            this.audience = audience;
        }

        public String getScopeClaim() {
            return scopeClaim;
        }

        public void setScopeClaim(String scopeClaim) {
            this.scopeClaim = scopeClaim;
        }

        public String getRolesClaim() {
            return rolesClaim;
        }

        public void setRolesClaim(String rolesClaim) {
            this.rolesClaim = rolesClaim;
        }

        public String getDiscoveryUri() {
            return discoveryUri;
        }

        public void setDiscoveryUri(String discoveryUri) {
            this.discoveryUri = discoveryUri;
        }

        public String getPrincipalClaim() {
            return principalClaim;
        }

        public void setPrincipalClaim(String principalClaim) {
            this.principalClaim = principalClaim;
        }

        public String getRedirectUri() {
            return redirectUri;
        }

        public void setRedirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
        }

        public String getCustomLoginRoute() {
            return customLoginRoute;
        }

        public void setCustomLoginRoute(String customLoginRoute) {
            this.customLoginRoute = customLoginRoute;
        }

        public List<String> getScopes() {
            return scopes;
        }

        public void setScopes(List<String> scopes) {
            this.scopes = scopes;
        }
    }
}
