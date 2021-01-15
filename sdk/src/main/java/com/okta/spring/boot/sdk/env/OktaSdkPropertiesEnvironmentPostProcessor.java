/*
 * Copyright 2017-Present Okta, Inc.
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
package com.okta.spring.boot.sdk.env;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.util.StringUtils;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This {@link EnvironmentPostProcessor} configures additional {@link PropertySource}s for {code ~/.okta/okta.yaml} and {code ~/.okta/okta.yml}.
 */
final class OktaSdkPropertiesEnvironmentPostProcessor implements EnvironmentPostProcessor, Ordered {

    private static final String OKTA_CLIENT_ORG_URL = "okta.client.orgUrl";
    private static final String OKTA_OAUTH2_ISSUER = "okta.oauth2.issuer";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {

        environment.getPropertySources().addLast(loadYaml(new FileSystemResource(new File(System.getProperty("user.home"), ".okta/okta.yml")), false));
        environment.getPropertySources().addLast(loadYaml(new FileSystemResource(new File(System.getProperty("user.home"), ".okta/okta.yaml")), false));
        resolveEmptyOrgUrl(environment);
    }

    /**
     * If <code>'okta.client.orgUrl'</code> property is absent, try to resolve it from <code>'okta.oauth2.issuer'</code>.
     */
    private void resolveEmptyOrgUrl(ConfigurableEnvironment environment) {
        if (!StringUtils.hasText(environment.getProperty(OKTA_CLIENT_ORG_URL))) {
            String issuerValue = environment.getProperty(OKTA_OAUTH2_ISSUER);
            if (StringUtils.hasText(issuerValue)) {
                Map<String, Object> map = new HashMap<>();
                try {
                    map.put(OKTA_CLIENT_ORG_URL, new URL(new URL(issuerValue), "/").toString());
                } catch (MalformedURLException e) {
                    throw new RuntimeException(e);
                }
                environment.getPropertySources().addLast(new MapPropertySource("issuer-to-orgUrl", map));
            }
        }
    }

    private PropertySource<?> loadYaml(Resource resource, boolean required) {
        YamlPropertySourceLoader loader = new YamlPropertySourceLoader();
        if (!resource.exists() && required) {
            throw new IllegalArgumentException("Resource " + resource + " does not exist");
        }

        if (resource.exists()) {
            try {
                List<PropertySource<?>> list = loader.load(resource.getFilename(), resource);
                return list.get(0);
            } catch (IOException ex) {
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
}