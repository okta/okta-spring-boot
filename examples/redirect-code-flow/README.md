Okta Spring Security OAuth2 Code Flow Example
=============================================

Clone the project and build it!

```bash
$ git clone https://github.com/okta/okta-spring-security.git
$ cd okta-spring-security
$ mvn install
```

Change into this examples directory:

```bash
cd examples/redirect-code-flow
```

Run the example:
```bash
mvn spring-boot:run -Dokta.oauth2.clientId={yourClientId} -Dokta.oauth2.clientSecret={yourClientSecret} -Dokta.oauth2.issuer={yourOktaIssuerUrl} 
```
