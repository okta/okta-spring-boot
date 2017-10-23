package com.okta.test.mock.application

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.boot.SpringApplication
import org.springframework.context.ConfigurableApplicationContext

class SpringApplicationUnderTest implements ApplicationUnderTest {

    private final Logger logger = LoggerFactory.getLogger(SpringApplicationUnderTest)

    private ConfigurableApplicationContext applicationContext

    @Override
    void start() {
        applicationContext = SpringApplication.run(
                Class.forName(testScenario.command),
                testScenario.args.toArray(new String[testScenario.args.size()]))
    }

    @Override
    int stop() {

        if (applicationContext != null && applicationContext.isRunning()) {
            applicationContext.stop()
            return 0
        } else {
            logger.warn("Spring Application was not running")
            return 1
        }
    }
}
