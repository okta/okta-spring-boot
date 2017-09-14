package com.okta.spring.oauth.code;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class DiscoveryMetadata {

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

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    public void setAuthorizationEndpoint(String authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public void setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    public String getUserinfoEndpoint() {
        return userinfoEndpoint;
    }

    public void setUserinfoEndpoint(String userinfoEndpoint) {
        this.userinfoEndpoint = userinfoEndpoint;
    }

    public String getRegistrationEndpoint() {
        return registrationEndpoint;
    }

    public void setRegistrationEndpoint(String registrationEndpoint) {
        this.registrationEndpoint = registrationEndpoint;
    }

    public String getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }

    public String getIntrospectionEndpoint() {
        return introspectionEndpoint;
    }

    public void setIntrospectionEndpoint(String introspectionEndpoint) {
        this.introspectionEndpoint = introspectionEndpoint;
    }

    public String getRevocationEndpoint() {
        return revocationEndpoint;
    }

    public void setRevocationEndpoint(String revocationEndpoint) {
        this.revocationEndpoint = revocationEndpoint;
    }

    public String getEndSessionEndpoint() {
        return endSessionEndpoint;
    }

    public void setEndSessionEndpoint(String endSessionEndpoint) {
        this.endSessionEndpoint = endSessionEndpoint;
    }

    public List<String> getResponseTypesSupported() {
        return responseTypesSupported;
    }

    public void setResponseTypesSupported(List<String> responseTypesSupported) {
        this.responseTypesSupported = responseTypesSupported;
    }

    public List<String> getResponseModesSupported() {
        return responseModesSupported;
    }

    public void setResponseModesSupported(List<String> responseModesSupported) {
        this.responseModesSupported = responseModesSupported;
    }

    public List<String> getGrantTypesSupported() {
        return grantTypesSupported;
    }

    public void setGrantTypesSupported(List<String> grantTypesSupported) {
        this.grantTypesSupported = grantTypesSupported;
    }

    public List<String> getSubjectTypesSupported() {
        return subjectTypesSupported;
    }

    public void setSubjectTypesSupported(List<String> subjectTypesSupported) {
        this.subjectTypesSupported = subjectTypesSupported;
    }

    public List<String> getIdTokenSigningAlgValuesSupported() {
        return idTokenSigningAlgValuesSupported;
    }

    public void setIdTokenSigningAlgValuesSupported(List<String> idTokenSigningAlgValuesSupported) {
        this.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported;
    }

    public List<String> getScopesSupported() {
        return scopesSupported;
    }

    public void setScopesSupported(List<String> scopesSupported) {
        this.scopesSupported = scopesSupported;
    }

    public List<String> getTokenEndpointAuthMethodsSupported() {
        return tokenEndpointAuthMethodsSupported;
    }

    public void setTokenEndpointAuthMethodsSupported(List<String> tokenEndpointAuthMethodsSupported) {
        this.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported;
    }

    public List<String> getClaimsSupported() {
        return claimsSupported;
    }

    public void setClaimsSupported(List<String> claimsSupported) {
        this.claimsSupported = claimsSupported;
    }

    public List<String> getCodeChallengeMethodsSupported() {
        return codeChallengeMethodsSupported;
    }

    public void setCodeChallengeMethodsSupported(List<String> codeChallengeMethodsSupported) {
        this.codeChallengeMethodsSupported = codeChallengeMethodsSupported;
    }

    public List<String> getIntrospectionEndpointAuthMethodsSupported() {
        return introspectionEndpointAuthMethodsSupported;
    }

    public void setIntrospectionEndpointAuthMethodsSupported(List<String> introspectionEndpointAuthMethodsSupported) {
        this.introspectionEndpointAuthMethodsSupported = introspectionEndpointAuthMethodsSupported;
    }

    public List<String> getRevocationEndpointAuthMethodsSupported() {
        return revocationEndpointAuthMethodsSupported;
    }

    public void setRevocationEndpointAuthMethodsSupported(List<String> revocationEndpointAuthMethodsSupported) {
        this.revocationEndpointAuthMethodsSupported = revocationEndpointAuthMethodsSupported;
    }
}
