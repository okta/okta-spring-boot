package com.okta.test.mock.application

import com.okta.test.mock.TestScenario

trait ApplicationUnderTest {

    private TestScenario testScenario

    abstract void start()

    abstract int stop()

    TestScenario getTestScenario() {
        return testScenario
    }

    ApplicationUnderTest configure(TestScenario testScenario) {
        this.testScenario = testScenario
        return this
    }
}
