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

public class OktaEnvironmentPostProcessorApplicationListener implements SmartApplicationListener, Ordered {

    private static final Logger log = LoggerFactory.getLogger(OktaEnvironmentPostProcessorApplicationListener.class);

    @Override
    public void onApplicationEvent(ApplicationEvent event) {
        if (event instanceof ApplicationPreparedEvent) {
            ConfigurableEnvironment environment = ((ApplicationPreparedEvent) event).getApplicationContext().getEnvironment();
            ValidationResponse validationResponse = ConfigurationValidator.validateIssuer(environment.getProperty("okta.oauth2.issuer"));
            if (!validationResponse.isValid()) {
                log.warn(validationResponse.getMessage());
            }
        }
    }

    @Override
    public boolean supportsEventType(Class<? extends ApplicationEvent> eventType) {
        return ApplicationPreparedEvent.class.isAssignableFrom(eventType);
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }
}
