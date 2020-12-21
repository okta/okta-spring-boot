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
package com.okta.spring.boot.oauth.env

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.LoggerContext
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import org.slf4j.LoggerFactory
import org.springframework.boot.context.event.ApplicationPreparedEvent
import org.springframework.context.ConfigurableApplicationContext
import org.springframework.core.env.MapPropertySource
import org.springframework.mock.env.MockEnvironment
import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.is
import static org.mockito.Mockito.mock
import static org.mockito.Mockito.when

class OktaEnvironmentPostProcessorApplicationListenerTest {

    private static final String LOGGER_NAME = OktaEnvironmentPostProcessorApplicationListener.getName()
    private static final String MSG = "Your Okta Issuer URL is missing. You can copy your domain from the Okta Developer Console. " +
        "Follow these instructions to find it: https://bit.ly/finding-okta-domain" + System.lineSeparator() +
        "To fix this add the `okta.oauth2.issuer` property to your application environments."
    private static final Logger log = (Logger) LoggerFactory.getLogger(LOGGER_NAME)

    def event = mock(ApplicationPreparedEvent)
    def context = mock(ConfigurableApplicationContext)

    @Test
    void testValidIssuerProperty() {
        LogsAppender logsAppender = new LogsAppender()
        logsAppender.start()
        log.addAppender(logsAppender)

        buildApplicationEvent([
            "okta.oauth2.issuer": "https://issuer.example.com/foobar"
        ])
        new OktaEnvironmentPostProcessorApplicationListener().onApplicationEvent(event)

        def logs = logsAppender.getLogs(LOGGER_NAME)

        assertThat "The logs list must be empty", logs.isEmpty(), is(true)
        assertThat "Should be no WARN messages", logsAppender.contains(Level.WARN), is(false)

        log.detachAppender(logsAppender)
    }

    @Test
    void testEmptyIssuer() {
        LogsAppender logsAppender = new LogsAppender()
        logsAppender.start()
        log.addAppender(logsAppender)

        buildApplicationEvent(Collections.emptyMap())
        new OktaEnvironmentPostProcessorApplicationListener().onApplicationEvent(event)

        def logs = logsAppender.getLogs(LOGGER_NAME)

        assertThat "Should be at least one WARN message", logsAppender.contains(Level.WARN), is(true)
        assertThat "Should be one message", logs.size(), is(1)
        assertThat "Wrong level", logs.get(0).getLevel(), is(Level.WARN)
        assertThat "Wrong message", logs.get(0).getMessage(), is(MSG)

        log.detachAppender(logsAppender)
    }

    private void buildApplicationEvent(Map<String, Object> properties) {
        def environment = new MockEnvironment()
        environment.getPropertySources().addFirst(new MapPropertySource("test", properties))
        when(context.getEnvironment()).thenReturn(environment)
        when(event.getApplicationContext()).thenReturn(context)
    }

    private static final class LogsAppender extends ListAppender<ILoggingEvent> {
        private final Thread thread

        LogsAppender() {
            thread = Thread.currentThread()
            setContext((LoggerContext) LoggerFactory.getILoggerFactory())
        }

        @Override
        protected void append(ILoggingEvent iLoggingEvent) {
            if (Thread.currentThread().equals(thread)) {
                super.append(iLoggingEvent)
            }
        }

        boolean contains(Level level) {
            return this.list.stream()
                .anyMatch { event -> event.getLevel().equals(level) }
        }

        List<ILoggingEvent> getLogs(String loggerName) {
            return this.list.stream()
                .filter { event -> event.getLoggerName().contains(loggerName) }
                .collect()
        }
    }
}
