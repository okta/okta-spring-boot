/*
 * Copyright 2018-Present Okta, Inc.
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

import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.util.StringUtils;

/**
 * Condition to check if a {@code okta.oauth2.issuer} is specified.
 *
 * @since 0.6.0
 */
public class IssuerCondition extends SpringBootCondition {

    @Override
    public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
        String issuer = context.getEnvironment().getProperty("okta.oauth2.issuer");
        ConditionMessage.Builder message = ConditionMessage.forCondition("Okta OAuth2 Issuer");
        if (StringUtils.hasLength(issuer)) {
            return ConditionOutcome.match(message.foundExactly("okta.oauth2.issuer property"));
        }
        return ConditionOutcome.noMatch(message.didNotFind("okta.oauth2.issuer property").atAll());
    }
}