package com.okta.spring.boot.oauth.http

import org.hamcrest.MatcherAssert
import org.hamcrest.Matchers
import org.springframework.util.Assert
import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*

class VersionTest {

    @Test
    void testGetClientVersion() {
        assertThat Version.clientVersion, allOf(not(emptyString()),
                                                containsString("."),
                                                not(containsString("\$")))
    }

    @Test
    void testVersionUtil() {
        assertThat VersionUtil.userAgentsFromVersionMetadata(), containsString("okta-spring-security/${Version.clientVersion}")
    }

}
