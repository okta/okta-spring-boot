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
package com.okta.spring.oauth.discovery;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * OIDC discovery metadata represented as a simple bean.
 * @since 0.2.0
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class OidcDiscoveryMetadata {

    private String issuer;

    @JsonProperty("authorization_endpoint")
    private String authorizationEndpoint;

    @JsonProperty("token_endpoint")
    private String tokenEndpoint;

    @JsonProperty("userinfo_endpoint")
    private String userinfoEndpoint;

    @JsonProperty("registration_endpoint")
    private String registrationEndpoint;

    @JsonProperty("jwks_uri")
    private String jwksUri;

    @JsonProperty("introspection_endpoint")
    private String introspectionEndpoint;

    @JsonProperty("revocation_endpoint")
    private String revocationEndpoint;

    @JsonProperty("end_session_endpoint")
    private String endSessionEndpoint;

    @JsonProperty("response_types_supported")
    private List<String> responseTypesSupported;

    @JsonProperty("response_modes_supported")
    private List<String> responseModesSupported;

    @JsonProperty("grant_types_supported")
    private List<String> grantTypesSupported;

    @JsonProperty("subject_types_supported")
    private List<String> subjectTypesSupported;

    @JsonProperty("id_token_signing_alg_values_supported")
    private List<String> idTokenSigningAlgValuesSupported;

    @JsonProperty("scopes_supported")
    private List<String> scopesSupported;

    @JsonProperty("token_endpoint_auth_methods_supported")
    private List<String> tokenEndpointAuthMethodsSupported;

    @JsonProperty("claims_supported")
    private List<String> claimsSupported;

    @JsonProperty("code_challenge_methods_supported")
    private List<String> codeChallengeMethodsSupported;

    @JsonProperty("introspection_endpoint_auth_methods_supported")
    private List<String> introspectionEndpointAuthMethodsSupported;

    @JsonProperty("revocation_endpoint_auth_methods_supported")
    private List<String> revocationEndpointAuthMethodsSupported;

    public String getIssuer() {
        return issuer;
    }

    public OidcDiscoveryMetadata setIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    public String getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    public OidcDiscoveryMetadata setAuthorizationEndpoint(String authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
        return this;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public OidcDiscoveryMetadata setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
        return this;
    }

    public String getUserinfoEndpoint() {
        return userinfoEndpoint;
    }

    public OidcDiscoveryMetadata setUserinfoEndpoint(String userinfoEndpoint) {
        this.userinfoEndpoint = userinfoEndpoint;
        return this;
    }

    public String getRegistrationEndpoint() {
        return registrationEndpoint;
    }

    public OidcDiscoveryMetadata setRegistrationEndpoint(String registrationEndpoint) {
        this.registrationEndpoint = registrationEndpoint;
        return this;
    }

    public String getJwksUri() {
        return jwksUri;
    }

    public OidcDiscoveryMetadata setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
        return this;
    }

    public String getIntrospectionEndpoint() {
        return introspectionEndpoint;
    }

    public OidcDiscoveryMetadata setIntrospectionEndpoint(String introspectionEndpoint) {
        this.introspectionEndpoint = introspectionEndpoint;
        return this;
    }

    public String getRevocationEndpoint() {
        return revocationEndpoint;
    }

    public OidcDiscoveryMetadata setRevocationEndpoint(String revocationEndpoint) {
        this.revocationEndpoint = revocationEndpoint;
        return this;
    }

    public String getEndSessionEndpoint() {
        return endSessionEndpoint;
    }

    public OidcDiscoveryMetadata setEndSessionEndpoint(String endSessionEndpoint) {
        this.endSessionEndpoint = endSessionEndpoint;
        return this;
    }

    public List<String> getResponseTypesSupported() {
        return responseTypesSupported;
    }

    public OidcDiscoveryMetadata setResponseTypesSupported(List<String> responseTypesSupported) {
        this.responseTypesSupported = responseTypesSupported;
        return this;
    }

    public List<String> getResponseModesSupported() {
        return responseModesSupported;
    }

    public OidcDiscoveryMetadata setResponseModesSupported(List<String> responseModesSupported) {
        this.responseModesSupported = responseModesSupported;
        return this;
    }

    public List<String> getGrantTypesSupported() {
        return grantTypesSupported;
    }

    public OidcDiscoveryMetadata setGrantTypesSupported(List<String> grantTypesSupported) {
        this.grantTypesSupported = grantTypesSupported;
        return this;
    }

    public List<String> getSubjectTypesSupported() {
        return subjectTypesSupported;
    }

    public OidcDiscoveryMetadata setSubjectTypesSupported(List<String> subjectTypesSupported) {
        this.subjectTypesSupported = subjectTypesSupported;
        return this;
    }

    public List<String> getIdTokenSigningAlgValuesSupported() {
        return idTokenSigningAlgValuesSupported;
    }

    public OidcDiscoveryMetadata setIdTokenSigningAlgValuesSupported(List<String> idTokenSigningAlgValuesSupported) {
        this.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported;
        return this;
    }

    public List<String> getScopesSupported() {
        return scopesSupported;
    }

    public OidcDiscoveryMetadata setScopesSupported(List<String> scopesSupported) {
        this.scopesSupported = scopesSupported;
        return this;
    }

    public List<String> getTokenEndpointAuthMethodsSupported() {
        return tokenEndpointAuthMethodsSupported;
    }

    public OidcDiscoveryMetadata setTokenEndpointAuthMethodsSupported(List<String> tokenEndpointAuthMethodsSupported) {
        this.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported;
        return this;
    }

    public List<String> getClaimsSupported() {
        return claimsSupported;
    }

    public OidcDiscoveryMetadata setClaimsSupported(List<String> claimsSupported) {
        this.claimsSupported = claimsSupported;
        return this;
    }

    public List<String> getCodeChallengeMethodsSupported() {
        return codeChallengeMethodsSupported;
    }

    public OidcDiscoveryMetadata setCodeChallengeMethodsSupported(List<String> codeChallengeMethodsSupported) {
        this.codeChallengeMethodsSupported = codeChallengeMethodsSupported;
        return this;
    }

    public List<String> getIntrospectionEndpointAuthMethodsSupported() {
        return introspectionEndpointAuthMethodsSupported;
    }

    public OidcDiscoveryMetadata setIntrospectionEndpointAuthMethodsSupported(List<String> introspectionEndpointAuthMethodsSupported) {
        this.introspectionEndpointAuthMethodsSupported = introspectionEndpointAuthMethodsSupported;
        return this;
    }

    public List<String> getRevocationEndpointAuthMethodsSupported() {
        return revocationEndpointAuthMethodsSupported;
    }

    public OidcDiscoveryMetadata setRevocationEndpointAuthMethodsSupported(List<String> revocationEndpointAuthMethodsSupported) {
        this.revocationEndpointAuthMethodsSupported = revocationEndpointAuthMethodsSupported;
        return this;
    }
}
