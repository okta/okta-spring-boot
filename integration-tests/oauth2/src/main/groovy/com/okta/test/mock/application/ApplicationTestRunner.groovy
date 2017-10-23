package com.okta.test.mock.application

import com.okta.test.mock.Config
import com.okta.test.mock.Scenario
import com.okta.test.mock.TestScenario
import com.okta.test.mock.wiremock.HttpMock
import groovy.text.StreamingTemplateEngine
import org.junit.Assert
import org.testng.annotations.AfterClass
import org.testng.annotations.BeforeClass
import org.testng.util.Strings
import org.yaml.snakeyaml.Yaml

import java.util.stream.Collectors

import static org.hamcrest.Matchers.is
import static org.hamcrest.MatcherAssert.assertThat

abstract class ApplicationTestRunner implements HttpMock {

    private ApplicationUnderTest app = getApplicationUnderTest(getScenarioName())

    private mockPort
    private applicationPort

    String getScenarioName() {
        Scenario scenario = getClass().getAnnotation(Scenario)
        if (scenario == null || Strings.isNullOrEmpty(scenario.value())) {
            Assert.fail("@Scenario was not found on class '${getClass()}', you must annotate this class or override the 'getScenarioName()' method.")
        }
        return scenario.value()
    }

    int getApplicationPort() {
        return applicationPort
    }

    int doGetMockPort() {
        return mockPort
    }

    @BeforeClass
    void start() {
        startMockServer()
        app.start()
    }
    
    @AfterClass
    void stop() {
        assertThat(app.stop(), is(0))
    }

    ApplicationUnderTest getApplicationUnderTest(String scenarioName) {

        Config config = new Yaml().loadAs(getClass().getResource( '/testRunner.yml' ).text, Config)

        Class impl = Class.forName(config.implementation)
        TestScenario scenario = config.scenarios.get(scenarioName)

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