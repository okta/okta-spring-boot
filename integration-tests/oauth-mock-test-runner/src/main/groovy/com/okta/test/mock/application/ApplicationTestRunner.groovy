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
package com.okta.test.mock.application

import com.okta.test.mock.Config
import com.okta.test.mock.Scenario
import com.okta.test.mock.TestScenario
import com.okta.test.mock.wiremock.HttpMock
import groovy.text.StreamingTemplateEngine
import org.junit.Assert
import org.testng.annotations.AfterClass
import org.testng.annotations.BeforeClass
import org.testng.annotations.BeforeMethod
import org.testng.SkipException; 
import org.testng.util.Strings
import org.yaml.snakeyaml.Yaml

import java.lang.reflect.Method;
import java.util.stream.Collectors

import static io.restassured.RestAssured.given
import static org.hamcrest.MatcherAssert.assertThat

abstract class ApplicationTestRunner extends HttpMock {

    private ApplicationUnderTest app = getApplicationUnderTest(getScenarioName())

    private int mockPort
    private int applicationPort
    private TestScenario scenario

    ApplicationTestRunner() {
        setScenario(getScenarioName())
    }

    String getScenarioName() {
        Scenario scenario = getClass().getAnnotation(Scenario)
        if (scenario == null) {
            Assert.fail("@Scenario was not found on class '${getClass()}', you must annotate this class or override the 'getScenarioName()' method.")
        }
        return scenario.value().id
    }

    int getApplicationPort() {
        return applicationPort
    }

    int doGetMockPort() {
        return mockPort
    }

    @BeforeMethod
    void checkToRun(Method method) {
        for (String disabledTest : scenario.disabledTests) {
            if (method.getName().equals(disabledTest)) {
                throw new SkipException("Skipping the disabled test - " + disabledTest)
            }
        }
    }

    @BeforeClass
    void start() {
        startMockServer()
        app.start()

        // allow for CI to configure the timeout
        String retryCountKey = "okta.test.startPollCount"
        String envRetryCountKey = retryCountKey.replace('.', '_').toUpperCase(Locale.ENGLISH)
        String value = System.getenv(envRetryCountKey) ?: System.getProperty(retryCountKey, "10000") // a little over a minute

        pollForStartedApplication(applicationPort, value.toInteger())
    }
    
    @AfterClass
    void stop() {
        int exitStatus = app.stop()
        assertThat("exit status was not 0 or 143 (SIGTERM)", exitStatus==0 || exitStatus==143)
    }

    boolean pollForStartedApplication(int port, int times) {

        for (int ii=0; ii<times; ii++) {
            try {
                given().get("http://localhost:${port}/")
                return true
            } catch (ConnectException e) {
                // ignore connection exception
                Thread.sleep(500)
            }
        }
        return false
    }

    ApplicationUnderTest getApplicationUnderTest(String scenarioName) {

        Config config = new Yaml().loadAs(getClass().getResource( '/testRunner.yml' ).text, Config)

        Class impl = Class.forName(config.implementation)
        scenario = config.scenarios.get(scenarioName)

        // figure out which ports we need
        applicationPort = getPort("applicationPort", scenario)
        mockPort = getPort("mockPort", scenario)

        // interpolate the scenario args with the ports
        def templateEngine = new StreamingTemplateEngine()
        def binding = [applicationPort: applicationPort, mockPort: mockPort]
        List<String> filteredArgs = scenario.args.stream()
            .map { templateEngine.createTemplate(it).make(binding).toString() }
            .collect(Collectors.toList())
        scenario.args = filteredArgs

        // create and return
        return impl.newInstance()
                .configure(scenario)
    }

    int getPort(String key, TestScenario scenario) {
        Integer port = scenario.ports.get(key)
        if (port == null || port == 0) {
            return getFreePort()
        }
        return port
    }

    int getFreePort() {
        int port = new ServerSocket(0).withCloseable {it.getLocalPort()}
        return port
    }
}