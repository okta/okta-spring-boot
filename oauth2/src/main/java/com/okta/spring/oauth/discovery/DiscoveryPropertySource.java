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

import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.Environment;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * A {@link org.springframework.core.env.PropertySource PropertySource} that maps the values from an OIDC discovery
 * metadata endpoint to Spring Security's expected {code}security.oauth2.*{code} properties.
 * <p>
 * NOTE: Discovery can be disabled by setting the property {code}okta.oauth2.discoveryDisabled=true{code}.
 *
 * @since 0.3.0
 */
public class DiscoveryPropertySource extends EnumerablePropertySource<String> {

    private static final String OKTA_OAUTH_ISSUER = "okta.oauth2.issuer";
    private static final String OKTA_OAUTH_DISCOVERY_DISABLED = "okta.oauth2.discoveryDisabled";

    private static final String PREFIX = "discovery.";
    private static final String TOKEN_ENDPOINT_KEY = "token-endpoint";
    private static final String AUTHORIZATION_ENDPOINT_KEY = "authorization-endpoint";
    private static final String USERINFO_ENDPOINT_KEY = "userinfo-endpoint";
    private static final String JWKS_URI_KEY = "jwks-uri";
    private static final String INTROSPECTION_ENDPOINT_KEY = "introspection-endpoint";

    private static final String[] SUPPORTED_KEYS = {
                                            PREFIX + TOKEN_ENDPOINT_KEY,
                                            PREFIX + AUTHORIZATION_ENDPOINT_KEY,
                                            PREFIX + USERINFO_ENDPOINT_KEY,
                                            PREFIX + JWKS_URI_KEY,
                                            PREFIX + INTROSPECTION_ENDPOINT_KEY};

    private final boolean isEnabled;
    private final Environment environment;
    private Map<String, Object> metadataProperties = null;

    public DiscoveryPropertySource(Environment environment) {
        super("Okta-OIDC-Discovery-Client");
        this.environment = environment;
        this.isEnabled = !Boolean.parseBoolean(environment.getProperty(OKTA_OAUTH_DISCOVERY_DISABLED));
    }

    @Override
    public Object getProperty(String name) {
        // there are some cases where 'containsProperty' is not called before calling this method, so we need to guard
        // against it because we are using the 'environment' direction, otherwise we would end up recursively
        // calling this method.
        return isReady()
            ? getDiscoveryMetadata().get(name)
            : null;
    }

    @Override
    public boolean containsProperty(String name) {
        return isEnabled && metadataProperties != null && metadataProperties.containsKey(name);
    }

    @Override
    public String[] getPropertyNames() {
        return Arrays.copyOf(SUPPORTED_KEYS, SUPPORTED_KEYS.length);
    }

    private boolean isReady() {
        return environment.containsProperty(OKTA_OAUTH_ISSUER);
    }

    private Map<String, Object> getDiscoveryMetadata() {

        if (!isEnabled) {
            return Collections.emptyMap();
        }

        // lazy load the properties the first time they are actually used
        if (metadataProperties == null) {
            synchronized (this) {
                String issuerUrl = environment.getRequiredProperty(OKTA_OAUTH_ISSUER);
                OidcDiscoveryMetadata discoveryMetadata = createDiscoveryClient(issuerUrl).discover();
                Map<String, Object> tmpValues = new HashMap<>();

                if (discoveryMetadata != null) {
                    putIfNotNull(tmpValues, TOKEN_ENDPOINT_KEY, discoveryMetadata.getTokenEndpoint());
                    putIfNotNull(tmpValues, AUTHORIZATION_ENDPOINT_KEY, discoveryMetadata.getAuthorizationEndpoint());
                    putIfNotNull(tmpValues, USERINFO_ENDPOINT_KEY, discoveryMetadata.getUserinfoEndpoint());
                    putIfNotNull(tmpValues, JWKS_URI_KEY, discoveryMetadata.getJwksUri());
                    putIfNotNull(tmpValues, INTROSPECTION_ENDPOINT_KEY, discoveryMetadata.getIntrospectionEndpoint());
                }
                metadataProperties = tmpValues;
            }
        }
        return metadataProperties;
    }

    private static void putIfNotNull(Map<String, Object> map, String key, Object value) {
        if (value != null) {
            map.put(PREFIX + key, value);
        }
    }

    // exposed for testing
    OidcDiscoveryClient createDiscoveryClient(String issuerUrl) {
        return  new OidcDiscoveryClient(issuerUrl);
    }
}