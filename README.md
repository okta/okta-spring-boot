okta-spring-security
====================

Still some work to be done on this README.

For now here are the basics:

  - okta-spring-security-starter: a Spring Boot starter use to configure an implicit flow access token validation.
  - examples/siw-jquery - is a Spring Boot example backend with a static single page client.

Build the code:
``` bash
mvn clean install
```

Pre-commit, to include license header checking, PMD, and Findbugs (including find-sec-bugs) use the `ci` profile:
``` bash
# can only be run from the root of the project
mvn clean install -Pci
```


- Requires a custom Authorization Server, (instructions to be added soon)

Run the example:
``` bash
cd examples/siw-jquery
mvn spring-boot:run \
-Dokta.oauth.issuer=https://{yourOktaDomain}/oauth2/{yourAuthorizationServerId} \
-Dokta.oauth.audience={yourAuthorizationServerAudience} \
-Dokta.oauth.clientId={oauthClientId} \
-Dokta.oauth.rolesClaim={customRoleClaim) # defaults to 'groups'
```

Browse to: http://localhost:8080
