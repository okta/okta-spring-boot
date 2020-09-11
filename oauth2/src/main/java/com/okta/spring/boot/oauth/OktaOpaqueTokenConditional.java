package com.okta.spring.boot.oauth;

import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

public class OktaOpaqueTokenConditional extends AllNestedConditions {

    public OktaOpaqueTokenConditional() {
        super(ConfigurationPhase.REGISTER_BEAN);
    }

    @ConditionalOnProperty(name="okta.oauth2.clientId")
    static class ClientIdCondition { }

    @ConditionalOnProperty(name="okta.oauth2.clientSecret")
    static class ClientSecretCondition { }
}
