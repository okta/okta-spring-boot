/*
 * Copyright 2020-Present Okta, Inc.
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
package com.okta.spring.boot.oauth;

import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;

import java.net.URI;
import java.net.URL;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Okta's implementation of Spring security's interface {@link OpaqueTokenIntrospector} based on
 * {@link org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector}.
 */
public class OktaOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    private static final Logger log = LoggerFactory.getLogger(OktaOpaqueTokenIntrospector.class);

    private static final String ACCESS_TOKEN_TYPE_HINT = "access_token";

    private Converter<String, RequestEntity<?>> requestEntityConverter;
    private RestOperations restOperations;

    public OktaOpaqueTokenIntrospector(String introspectionUri, String clientId, String clientSecret, RestOperations restOperations) {
        Assert.notNull(introspectionUri, "introspectionUri cannot be null");
        Assert.notNull(clientId, "clientId cannot be null");
        Assert.notNull(clientSecret, "clientSecret cannot be null");
        Assert.notNull(restOperations, "restOperations cannot be null");
        this.requestEntityConverter = this.defaultRequestEntityConverter(URI.create(introspectionUri), clientId, clientSecret);
        this.restOperations = restOperations;
    }

    private Converter<String, RequestEntity<?>> defaultRequestEntityConverter(URI introspectionUri, String clientId, String clientSecret) {
        return (token) -> {
            HttpHeaders headers = this.requestHeaders();
            MultiValueMap<String, String> body = this.requestBody(token, clientId, clientSecret);
            return new RequestEntity(body, headers, HttpMethod.POST, introspectionUri);
        };
    }

    private HttpHeaders requestHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        return headers;
    }

    /**
     * Okta Introspection endpoint requires caller to send client_id, client_secret & token_type_hint
     * parameters in request body addition to token.
     */
    private MultiValueMap<String, String> requestBody(String token, String clientId, String clientSecret) {
        MultiValueMap<String, String> body = new LinkedMultiValueMap();
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("token_type_hint", ACCESS_TOKEN_TYPE_HINT);
        body.add("token", token);
        return body;
    }

    public OAuth2AuthenticatedPrincipal introspect(String token) {

        RequestEntity<?> requestEntity = (RequestEntity)this.requestEntityConverter.convert(token);
        if (requestEntity == null) {
            throw new OAuth2IntrospectionException("requestEntityConverter returned a null entity");
        } else {
            ResponseEntity<String> responseEntity = this.makeRequest(requestEntity);
            log.debug("Response from introspection endpoint: {}", responseEntity.getBody());
            HTTPResponse httpResponse = this.adaptToNimbusResponse(responseEntity);
            TokenIntrospectionResponse introspectionResponse = this.parseNimbusResponse(httpResponse);
            TokenIntrospectionSuccessResponse introspectionSuccessResponse = this.castToNimbusSuccess(introspectionResponse);
            if (!introspectionSuccessResponse.isActive()) {
                throw new BadOpaqueTokenException("Provided token isn't active");
            } else {
                return this.convertClaimsSet(introspectionSuccessResponse);
            }
        }
    }

    public void setRequestEntityConverter(Converter<String, RequestEntity<?>> requestEntityConverter) {
        Assert.notNull(requestEntityConverter, "requestEntityConverter cannot be null");
        this.requestEntityConverter = requestEntityConverter;
    }

    private ResponseEntity<String> makeRequest(RequestEntity<?> requestEntity) {
        log.debug("Making request to introspection endpoint");
        try {
            return this.restOperations.exchange(requestEntity, String.class);
        } catch (Exception var3) {
            throw new OAuth2IntrospectionException(var3.getMessage(), var3);
        }
    }

    private HTTPResponse adaptToNimbusResponse(ResponseEntity<String> responseEntity) {
        HTTPResponse response = new HTTPResponse(responseEntity.getStatusCodeValue());
        response.setHeader("Content-Type", new String[]{responseEntity.getHeaders().getContentType().toString()});
        response.setContent((String)responseEntity.getBody());
        if (response.getStatusCode() != 200) {
            throw new OAuth2IntrospectionException("Introspection endpoint responded with " + response.getStatusCode());
        } else {
            return response;
        }
    }

    private TokenIntrospectionResponse parseNimbusResponse(HTTPResponse response) {
        try {
            return TokenIntrospectionResponse.parse(response);
        } catch (Exception var3) {
            throw new OAuth2IntrospectionException(var3.getMessage(), var3);
        }
    }

    private TokenIntrospectionSuccessResponse castToNimbusSuccess(TokenIntrospectionResponse introspectionResponse) {
        if (!introspectionResponse.indicatesSuccess()) {
            throw new OAuth2IntrospectionException("Token introspection failed");
        } else {
            return (TokenIntrospectionSuccessResponse)introspectionResponse;
        }
    }

    private OAuth2AuthenticatedPrincipal convertClaimsSet(TokenIntrospectionSuccessResponse response) {
        Collection<GrantedAuthority> authorities = new ArrayList();
        Map<String, Object> claims = response.toJSONObject();
        Iterator var5;
        if (response.getAudience() != null) {
            List<String> audiences = new ArrayList();
            var5 = response.getAudience().iterator();

            while(var5.hasNext()) {
                Audience audience = (Audience)var5.next();
                audiences.add(audience.getValue());
            }

            claims.put("aud", Collections.unmodifiableList(audiences));
        }

        if (response.getClientID() != null) {
            claims.put("client_id", response.getClientID().getValue());
        }

        Instant iat;
        if (response.getExpirationTime() != null) {
            iat = response.getExpirationTime().toInstant();
            claims.put("exp", iat);
        }

        if (response.getIssueTime() != null) {
            iat = response.getIssueTime().toInstant();
            claims.put("iat", iat);
        }

        if (response.getIssuer() != null) {
            claims.put("iss", this.issuer(response.getIssuer().getValue()));
        }

        if (response.getNotBeforeTime() != null) {
            claims.put("nbf", response.getNotBeforeTime().toInstant());
        }

        if (response.getScope() != null) {
            List<String> scopes = Collections.unmodifiableList(response.getScope().toStringList());
            claims.put("scope", scopes);
            var5 = scopes.iterator();

            while(var5.hasNext()) {
                String scope = (String)var5.next();
                StringBuilder var10003 = new StringBuilder();
                this.getClass();
                authorities.add(new SimpleGrantedAuthority(var10003.append("SCOPE_").append(scope).toString()));
            }
        }

        return new DefaultOAuth2AuthenticatedPrincipal(claims, authorities);
    }

    private URL issuer(String uri) {
        try {
            return new URL(uri);
        } catch (Exception var3) {
            throw new OAuth2IntrospectionException("Invalid iss value: " + uri);
        }
    }
}
