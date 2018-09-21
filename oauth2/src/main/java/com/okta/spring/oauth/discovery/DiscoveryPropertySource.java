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

import com.okta.commons.configcheck.ConfigurationValidator;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.Environment;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
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

    private static final String OAUTH_CLIENT_PREFIX = "security.oauth2.client.";
    private static final String OAUTH_RESOURCE_PREFIX = "security.oauth2.resource.";
    private static final String OKTA_OAUTH_ISSUER = "okta.oauth2.issuer";
    private static final String OKTA_OAUTH_DISCOVERY_DISABLED = "okta.oauth2.discoveryDisabled";

    private static final String OAUTH_RESOURCE_JWK_SUB_KEY = OAUTH_RESOURCE_PREFIX + "jwk";

    private static final String OAUTH_ACCESS_TOKEN_URI_KEY = OAUTH_CLIENT_PREFIX + "accessTokenUri";
    private static final String OAUTH_ACCESS_USER_AUTH_URI_KEY = OAUTH_CLIENT_PREFIX + "userAuthorizationUri";
    private static final String OAUTH_ACCESS_USER_INFO_URI_KEY = OAUTH_RESOURCE_PREFIX + "userInfoUri";
    private static final String OAUTH_RESOURCE_JWT_KEY_SET_URI_KEY = OAUTH_RESOURCE_JWK_SUB_KEY + ".keySetUri";
    private static final String OAUTH_RESOURCE_JWT_KEY_SET_URI_DASH_KEY = OAUTH_RESOURCE_JWK_SUB_KEY + ".key-set-uri";
    private static final String OAUTH_RESOURCE_TOKEN_INFO_URI = OAUTH_RESOURCE_PREFIX + "tokenInfoUri";

    private static final String[] supportedKeys = {OAUTH_ACCESS_TOKEN_URI_KEY,
                                                   OAUTH_ACCESS_USER_AUTH_URI_KEY,
                                                   OAUTH_ACCESS_USER_INFO_URI_KEY,
                                                   OAUTH_RESOURCE_JWK_SUB_KEY,
                                                   OAUTH_RESOURCE_JWT_KEY_SET_URI_KEY,
                                                   OAUTH_RESOURCE_JWT_KEY_SET_URI_DASH_KEY,
                                                   OAUTH_RESOURCE_TOKEN_INFO_URI};
    private static final List<String> supportedKeysList = Collections.unmodifiableList(Arrays.asList(supportedKeys));


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
        return containsProperty(name) && isReady()
            ? getDiscoveryMetadata().get(name)
            : null;
    }

    @Override
    public boolean containsProperty(String name) {
        return isEnabled && supportedKeysList.contains(name);
    }

    @Override
    public String[] getPropertyNames() {
        return Arrays.copyOf(supportedKeys, supportedKeys.length);
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
                ConfigurationValidator.validateOrgUrl(issuerUrl);
                OidcDiscoveryMetadata discoveryMetadata = createDiscoveryClient(issuerUrl).discover();
                Map<String, Object> tmpValues = new HashMap<>();

                if (discoveryMetadata != null) {
                    putIfNotNull(tmpValues, OAUTH_ACCESS_TOKEN_URI_KEY, discoveryMetadata.getTokenEndpoint());
                    putIfNotNull(tmpValues, OAUTH_ACCESS_USER_AUTH_URI_KEY, discoveryMetadata.getAuthorizationEndpoint());
                    putIfNotNull(tmpValues, OAUTH_ACCESS_USER_INFO_URI_KEY, discoveryMetadata.getUserinfoEndpoint());
                    putIfNotNull(tmpValues, OAUTH_RESOURCE_JWT_KEY_SET_URI_KEY, discoveryMetadata.getJwksUri());
                    putIfNotNull(tmpValues, OAUTH_RESOURCE_JWT_KEY_SET_URI_DASH_KEY, discoveryMetadata.getJwksUri());
                    putIfNotNull(tmpValues, OAUTH_RESOURCE_TOKEN_INFO_URI, discoveryMetadata.getIntrospectionEndpoint());
                }
                metadataProperties = tmpValues;
            }
        }
        return metadataProperties;
    }

    private static void putIfNotNull(Map<String, Object> map, String key, Object value) {
        if (value != null) {
            map.put(key, value);
        }
    }

    OidcDiscoveryClient createDiscoveryClient(String issuerUrl) {
        return  new OidcDiscoveryClient(issuerUrl);
    }
}