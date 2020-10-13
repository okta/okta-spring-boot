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

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

class OktaOpaqueTokenIntrospectConditional extends AllNestedConditions {

    OktaOpaqueTokenIntrospectConditional() {
        super(ConfigurationPhase.REGISTER_BEAN);
    }

    @ConditionalOnProperty(name="okta.oauth2.client-id")
    static class ClientIdCondition { }

    @ConditionalOnProperty(name="okta.oauth2.client-secret")
    static class ClientSecretCondition { }

    @ConditionalOnProperty(name="okta.oauth2.issuer")
    static class IssuerCondition { }
}