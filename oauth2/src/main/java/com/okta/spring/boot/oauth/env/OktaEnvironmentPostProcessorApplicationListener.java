package com.okta.spring.boot.oauth.env;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationPreparedEvent;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.event.SmartApplicationListener;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;

public class OktaEnvironmentPostProcessorApplicationListener implements SmartApplicationListener, Ordered {

    private static final Logger log = LoggerFactory.getLogger(OktaEnvironmentPostProcessorApplicationListener.class);
    public static final String OKTA_OAUTH2_ISSUER = "okta.oauth2.issuer";

    @Override
    public void onApplicationEvent(ApplicationEvent event) {
        if (event instanceof ApplicationPreparedEvent) {
            ConfigurableEnvironment environment = ((ApplicationPreparedEvent) event).getApplicationContext().getEnvironment();
            String oktaOauth2Issuer = environment.getProperty(OKTA_OAUTH2_ISSUER);
            if (oktaOauth2Issuer == null || oktaOauth2Issuer.isEmpty()) {
                log.warn("Mandatory property `" + OKTA_OAUTH2_ISSUER + "` is missing.");
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
