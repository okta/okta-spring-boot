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

import com.okta.spring.oauth.discovery.OidcDiscoveryClient;
import com.okta.spring.oauth.discovery.OidcDiscoveryMetadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.web.client.ResourceAccessException;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class OktaPropertiesMappingEnvironmentPostProcessor implements EnvironmentPostProcessor {

    private static final String OAUTH_CLIENT_PREFIX = "security.oauth2.client.";
    private static final String OAUTH_RESOURCE_PREFIX = "security.oauth2.resource.";
    private static final String OKTA_OAUTH_PREFIX = "okta.oauth2.";

    private final Logger logger = LoggerFactory.getLogger(OktaPropertiesMappingEnvironmentPostProcessor.class);

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        environment.getPropertySources().addLast(remappedOktaToStandardOAuthPropertySource(environment));
        environment.getPropertySources().addLast(discoveryPropertiesSource(environment));
        environment.getPropertySources().addLast(loadYaml(new ClassPathResource("com/okta/spring/okta.yml")));
    }

    private PropertySource<?> loadYaml(Resource resource) {
        YamlPropertySourceLoader loader = new YamlPropertySourceLoader();
        if (!resource.exists()) {
            throw new IllegalArgumentException("Resource " + resource + " does not exist");
        }
        try {
            return loader.load("okta-defaults", resource, null);
        }
        catch (IOException ex) {
            throw new IllegalStateException("Failed to load yaml configuration from " + resource, ex);
        }
    }

    /**
     * Map {code}okta.oauth2.*{code} properties to {code}security.oauth2.*{code}.
     * @param environment Environment used to read the known 'okta' properties from.
     * @return A PropertySource containing the newly mapped values.
     */
    private PropertySource remappedOktaToStandardOAuthPropertySource(Environment environment) {
        Map<String, String> tmpValues = new HashMap<>();
        tmpValues.put(OAUTH_CLIENT_PREFIX + "clientId", environment.getProperty(OKTA_OAUTH_PREFIX + "clientId"));
        tmpValues.put(OAUTH_CLIENT_PREFIX + "clientSecret", environment.getProperty(OKTA_OAUTH_PREFIX + "clientSecret"));
        return new MapBasedPropertySource("okta-to-oauth2", Collections.unmodifiableMap(tmpValues));
    }

    /**
     * Maps OIDC discovery metadata properties to {code}security.oauth2.*{code}.
     * @param environment Environment used to read the {code}okta.oauth2.issuer{code} property from.
     * @return A PropertySource containing the newly mapped values.
     */
    private PropertySource discoveryPropertiesSource(Environment environment) {

        boolean discoveryDisabled = Boolean.parseBoolean(environment.getProperty(OKTA_OAUTH_PREFIX +"discoveryDisabled"));

        if (!discoveryDisabled) {
            String issuerUrl = environment.getProperty(OKTA_OAUTH_PREFIX +"issuer");
            try {
                OidcDiscoveryMetadata discoveryMetadata = new OidcDiscoveryClient(issuerUrl).discover();
                Map<String, String> tmpValues = new HashMap<>();

                String baseUrl = issuerUrl.substring(0, issuerUrl.lastIndexOf("/oauth2/"));
                tmpValues.put("okta.client.orgUrl", baseUrl);
                tmpValues.put(OAUTH_CLIENT_PREFIX + "accessTokenUri", discoveryMetadata.getTokenEndpoint());
                tmpValues.put(OAUTH_CLIENT_PREFIX + "userAuthorizationUri", discoveryMetadata.getAuthorizationEndpoint());
                tmpValues.put(OAUTH_RESOURCE_PREFIX + "userInfoUri", discoveryMetadata.getUserinfoEndpoint());
                return new MapBasedPropertySource("discovery-to-oauth2", Collections.unmodifiableMap(tmpValues));
            } catch (ResourceAccessException e) {
                logger.warn("Failed to discover oauth metadata from url: {}", issuerUrl, e);
            }
        }
        return new MapBasedPropertySource("no-discovery", Collections.emptyMap());
    }

    private static class MapBasedPropertySource extends EnumerablePropertySource<Map<String, String>> {

        MapBasedPropertySource(String name, Map<String, String> source) {
            super(name, source);
        }

        @Override
        public Object getProperty(String name) {
            return getSource().get(name);
        }

        @Override
        public String[] getPropertyNames() {
            return getSource().keySet().toArray(new String[getSource().size()]);
        }
    }
}
