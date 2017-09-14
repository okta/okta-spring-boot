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
package com.okta.spring.common;

import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;

@ConfigurationProperties("okta")
public class OktaOAuthProperties {

    /**
     * OAuth2 authorization properties. Typically found via a discovery/metadata endpoint.
     */
    private AuthorizationCodeResourceDetails client;

    /**
     * OAuth resource server and userinfo properties.
     */
    private ResourceServerProperties resource;

    /**
     * OIDC discovery URL, when set all properties that are discoverable will be populated automatically.
     */
    private String discoveryUri;

    /**
     * Okta organization base Url;
     */
    private String baseUrl;

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

    /**
     * Expected clientId value.
     */
    private String clientId;

    /**
     * Claim to pull the principal name from.
     */
    private String principalClaim = "email";

    /**
     * Login route path.
     */
    private String redirectUri = "/login";

    /**
     * Custom login page hosted by this application.
     */
    private String customLoginRoute;


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

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public AuthorizationCodeResourceDetails getClient() {
        return client;
    }

    public void setClient(AuthorizationCodeResourceDetails client) {
        this.client = client;
    }

    public String getDiscoveryUri() {
        return discoveryUri;
    }

    public void setDiscoveryUri(String discoveryUri) {
        this.discoveryUri = discoveryUri;
    }

    public ResourceServerProperties getResource() {
        return resource;
    }

    public void setResource(ResourceServerProperties resource) {
        this.resource = resource;
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

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }
}
