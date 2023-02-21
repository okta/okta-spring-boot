package com.okta.spring.boot.oauth.env;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.ResponseEntity;

public class OIDCMetadata {

    private final String clientAuthenticationMethod = "none";
    private final String scope = "profile,email,openid";
    private final String jwkSetURI;
    private final String authorizationURI;
    private final String tokenURI;
    private final String userInfoURI;
    private final String introspectionURI;

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
            // TODO Temp workaround as auth0 does not have this URL and spring boot config needs it
            this.introspectionURI = root.path("issuer").asText();
        }

        this.jwkSetURI = root.path("jwks_uri").asText();
        this.authorizationURI = root.path("authorization_endpoint").asText();
        this.tokenURI = root.path("token_endpoint").asText();
        this.userInfoURI = root.path("userinfo_endpoint").asText();
    }
}
