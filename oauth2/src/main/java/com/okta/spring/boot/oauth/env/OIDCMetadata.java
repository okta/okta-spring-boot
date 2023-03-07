/*
 * Copyright 2023-Present Okta, Inc.
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
package com.okta.spring.boot.oauth.env;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.ResponseEntity;

public class OIDCMetadata {

    private boolean isAuth0;
    private final String clientAuthenticationMethod = "none";
    private final String scope = "profile,email,openid";
    private final String jwkSetURI;
    private final String authorizationURI;
    private final String tokenURI;
    private final String userInfoURI;
    private final String introspectionURI;

    public boolean isAuth0() {
        return isAuth0;
    }

    public String getClientAuthenticationMethod() {
        return clientAuthenticationMethod;
    }

    public String getScope() {
        return scope;
    }

    public String getJwkSetURI() {
        return jwkSetURI;
    }

    public String getAuthorizationURI() {
        return authorizationURI;
    }

    public String getTokenURI() {
        return tokenURI;
    }

    public String getUserInfoURI() {
        return userInfoURI;
    }

    public String getIntrospectionURI() {
        return introspectionURI;
    }

    public OIDCMetadata(String issuerWithPathKey) {
        this.jwkSetURI = "${" + issuerWithPathKey + "}/v1/keys";
        this.authorizationURI = "${" + issuerWithPathKey + "}/v1/authorize";
        this.tokenURI = "${" + issuerWithPathKey + "}/v1/token";
        this.userInfoURI = "${" + issuerWithPathKey + "}/v1/userinfo";
        this.introspectionURI = "${" + issuerWithPathKey + "}/v1/introspect";
    }

    /**
     * Fetch metadata from the ${issuer}/.well-known/openid-configuration endpoint
     *
     * @param response well known metadata response
     */
    public OIDCMetadata(ResponseEntity<String> response) throws JsonProcessingException {

        ObjectMapper mapper = new ObjectMapper();
        JsonNode root = mapper.readTree(response.getBody());

        if (root.has("introspection_endpoint") && !root.path("introspection_endpoint").isNull()) {
            this.introspectionURI = root.path("introspection_endpoint").asText();
        } else {
            // auth0 does not have this URL
            this.introspectionURI = null;
            this.isAuth0 = true;
        }

        this.jwkSetURI = root.path("jwks_uri").asText();
        this.authorizationURI = root.path("authorization_endpoint").asText();
        this.tokenURI = root.path("token_endpoint").asText();
        this.userInfoURI = root.path("userinfo_endpoint").asText();
    }
}
