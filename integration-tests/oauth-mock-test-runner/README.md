Okta OAuth Test Suite
=====================

This is the start of an OAuth test suite based on [WireMock](http://wiremock.org/).

The goal of this project is to support _mostly_ black box testing against Okta's OAuth endpoints (specifically for testing error conditions, like a JWT token with an invalid token) 

This suite is runnable from a self contained jar (so you can integrate it with a non-java build tool)

You will need these things:
- The projects uberjar (this will be published in the near future, but for now see the build section below)
- testRunner.yml - See section below
- testng.xml - See section below (this will go away too, as we can programmatically configure TestNG)

## Available Scenarios:

- code-flow-local-validation - Code Flow with local access token validation 
- code-flow-remote-validation - Code Flow with remote access token validation
- implicit-flow-local-validation - Implicit Flow with local access token validation 
- implicit-flow-remote-validation - Implicit Flow with remote access token validation

## testRunner.yml

This is the file that defines how the test scenarios are run.

Example first:

```yml
scenarios:
  code-flow-local-validation:
    ports:
      applicationPort: 8080
      mockPort: 9090
    command: mvn
    args:
    - spring-boot:run
    - -Dtest.mainClass=com.okta.spring.tests.oauth2.code.BasicRedirectCodeFlowApplication
    - -Dserver.port=${applicationPort}
    - -Dokta.oauth2.issuer=http://localhost:${mockPort}/oauth2/default
    - -Dokta.oauth2.clientId=OOICU812
    - -Dokta.oauth2.clientSecret=VERY_SECRET
    - -Dserver.session.trackingModes=cookie
    - --batch-mode
```

- `scenarios` - The top level scenarios defines how the individual scenarios are run
- `ports` - Optional, if not defined the properties will be set to an available ephemeral port
- `command' - The script or bin to execute
- `args` - each args gets a new line

**Note:** The args will be interpolated with the two ports. The equivalent command line for the above block would be:
```bash
 mvn spring-boot:run \
       -Dtest.mainClass=com.okta.spring.tests.oauth2.code.BasicRedirectCodeFlowApplication \
       -Dserver.port=8080 \
       -Dokta.oauth2.issuer=http://localhost:9090/oauth2/default \
       -Dokta.oauth2.clientId=OOICU812 \
       -Dokta.oauth2.clientSecret=VERY_SECRET \
       -Dserver.session.trackingModes=cookie \
       --batch-mode
```

## testng.xml

Needed temporally, this allows customization of which tests to run. You will to need to understand the structure of classes and test in this project to configure one. See the [TestNG doc](http://testng.org/doc/documentation-main.html#testng-xml) for more info.

## Logging

Each forked process gets an individual log file in the format of `target/'${command}'-${date}`.

## Build this project!

This project can be build from this directory with a standard `mvn install`. This will create an uberjar located `target/okta-oauth-mock-test-runner-${target}-shaded.jar`.


## Run it already !

```java
java -cp ${directory-containing-testRunner.yml}:okta-oauth-mock-test-runner-${version}-shaded.jar org.testng.TestNG -d test-report-directory  your-testng.xml
```

**NOTE:** One the classpath is the directory containing your `testRunner.yml` not the file itself (this will likely be an arg in the future).

Test it out with this project:
```bash
cd ../oauth2
mkdir target
java -cp src/test/resources/:../oauth-mock-test-runner/target/okta-oauth-mock-test-runner-0.2.0-SNAPSHOT-shaded.jar org.testng.TestNG -d target/cli-test-output  ../oauth-mock-test-runner/src/main/resources/testng.xml
```

## Run Other Java tests?

Of course, bug @bdemers for details.