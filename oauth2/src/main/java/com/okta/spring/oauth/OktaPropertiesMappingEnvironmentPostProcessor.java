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

import com.okta.spring.oauth.discovery.DiscoveryPropertySource;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Environment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.List;

/**
 * This {@link EnvironmentPostProcessor} configures additional {@link PropertySource}s that map OIDC discovery metadata.
 *
 * As well as updating default properties values from 'com.okta.spring.okta.yml'. And setting 'okta.client.org-url' based
 * on 'okta.oauth2.issuer'
 *
 * NOTE: for discovery can be disabled by setting the property {code}okta.oauth2.discoveryDisabled=true{code}.
 *
 * @since 0.2.0
 */
public class OktaPropertiesMappingEnvironmentPostProcessor implements EnvironmentPostProcessor, Ordered {

    private static final String OKTA_OAUTH_PREFIX = "okta.oauth2.";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        environment.getPropertySources().addLast(loadYaml(new FileSystemResource(new File(System.getProperty("user.home"), ".okta/okta.yml")), false));
        environment.getPropertySources().addLast(loadYaml(new FileSystemResource(new File(System.getProperty("user.home"), ".okta/okta.yaml")), false));
        environment.getPropertySources().addLast(new DiscoveryPropertySource(environment));
        environment.getPropertySources().addLast(new IssuerToOrgUrlPropertySource(environment));
        environment.getPropertySources().addLast(loadYaml(new ClassPathResource("com/okta/spring/okta.yml"), true));
    }

    private PropertySource<?> loadYaml(Resource resource, boolean required) {
        YamlPropertySourceLoader loader = new YamlPropertySourceLoader();
        if (!resource.exists() && required) {
            throw new IllegalArgumentException("Resource " + resource + " does not exist");
        }

        if (resource.exists()) {
            try {

                // Spring Boot 2
                Method method = ClassUtils.getMethodIfAvailable(YamlPropertySourceLoader.class,"load", String.class, Resource.class);
                if (method != null) {
                    List<PropertySource<?>> list = (List<PropertySource<?>>) method.invoke(loader, resource.getFilename(), resource);
                    return list.get(0); // TODO: hack
                } else {
                    // Spring Boot 1.x
                    return loader.load(resource.getFilename(), resource, null);
                }
            } catch (IllegalAccessException | InvocationTargetException | IOException ex) {
                throw new IllegalStateException("Failed to load yaml configuration from " + resource, ex);
            }
        } else {
            return new MapPropertySource("Missing "+ resource.getFilename(), Collections.emptyMap());
        }
    }

    @Override
    public int getOrder() {
        return LOWEST_PRECEDENCE;
    }

    /**
     * Maps the baseUrl of {code}okta.oauth2.issuer{code} to {code}okta.client.org-url{code}.
     */
    static class IssuerToOrgUrlPropertySource extends PropertySource {

        private final Environment environment;

        IssuerToOrgUrlPropertySource(Environment environment) {
            super("okta-oauth-to-client");
            this.environment = environment;
        }

        @Override
        public Object getProperty(String name) {
            if (containsProperty(name)) {
                // first lookup the issuer
                String issuerUrl = environment.getProperty(OKTA_OAUTH_PREFIX + "issuer");
                // if we don't have one just return null
                if (StringUtils.hasText(issuerUrl)) {
                    return issuerUrl.substring(0, issuerUrl.lastIndexOf("/oauth2/"));
                }
            }
            return null;
        }

        @Override
        public boolean containsProperty(String name) {
            return "okta.client.org-url".equals(name) || "okta.client.orgUrl".equals(name);
        }
    }
}