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
package com.okta.spring.boot.oauth.env;

import com.okta.commons.configcheck.ConfigurationValidator;
import com.okta.commons.configcheck.ValidationResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationPreparedEvent;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.event.SmartApplicationListener;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class OktaEnvironmentPostProcessorApplicationListener implements SmartApplicationListener, Ordered {

    private static final Logger log = LoggerFactory.getLogger(OktaEnvironmentPostProcessorApplicationListener.class);

    /**
     * Active Spring profiles that automatically suppress the issuer validation warning.
     * Users can suppress validation for additional profiles via
     * {@code okta.oauth2.issuer-validation-skip-profiles}.
     */
    private static final Set<String> DEFAULT_SKIP_PROFILES = Stream.of(
            "test", "dev", "local", "mock", "offline"
    ).collect(Collectors.toSet());

    @Override
    public void onApplicationEvent(ApplicationEvent event) {
        if (event instanceof ApplicationPreparedEvent) {
            ConfigurableEnvironment environment = ((ApplicationPreparedEvent) event).getApplicationContext().getEnvironment();

            // Allow explicit opt-out via property
            String skipProperty = environment.getProperty("okta.oauth2.skip-issuer-validation");
            if ("true".equalsIgnoreCase(skipProperty)) {
                return;
            }

            // Collect extra skip-profiles configured by the user
            String extraProfiles = environment.getProperty("okta.oauth2.issuer-validation-skip-profiles", "");
            Set<String> skipProfiles = Stream.concat(
                DEFAULT_SKIP_PROFILES.stream(),
                Arrays.stream(extraProfiles.split(",")).map(String::trim).filter(s -> !s.isEmpty())
            ).collect(Collectors.toSet());

            // Skip validation when any active profile is in the skip set
            String[] activeProfiles = environment.getActiveProfiles();
            for (String profile : activeProfiles) {
                if (skipProfiles.contains(profile)) {
                    log.debug("Skipping Okta issuer validation for profile '{}'", profile);
                    return;
                }
            }

            ValidationResponse validationResponse = ConfigurationValidator.validateIssuer(environment.getProperty("okta.oauth2.issuer"));
            if (!validationResponse.isValid()) {
                log.warn(validationResponse.getMessage() + System.lineSeparator() +
                    "To fix this add the `okta.oauth2.issuer` property to your application environments.");
            }
        }
    }

    @Override
    public boolean supportsEventType(Class<? extends ApplicationEvent> eventType) {
        return ApplicationPreparedEvent.class.isAssignableFrom(eventType);
    }

    @Override
    public int getOrder() {
        return LOWEST_PRECEDENCE;
    }
}
