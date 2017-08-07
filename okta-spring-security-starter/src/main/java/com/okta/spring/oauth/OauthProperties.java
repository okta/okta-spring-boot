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

@ConfigurationProperties("okta.oauth")
public class OauthProperties {

    /**
     * Custom authorization server issuer URL: i.e. 'https://dev-123456.oktapreview.com/oauth2/ausar5cbq5TRooicu812'.
     */
    private String issuer;

    /**
     * Expected access token audience claim value.
     */
    private String audience = "all";

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
}
