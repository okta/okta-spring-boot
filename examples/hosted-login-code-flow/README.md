Okta Spring Security OAuth Code Flow Example
=============================================

Clone the project and build it!

```bash
$ git clone https://github.com/okta/okta-spring-boot.git
$ cd okta-spring-security
$ mvn install
```

Change into this examples directory:

```bash
cd examples/hosted-login-code-flow
```

Run the example:
```bash
mvn spring-boot:run -Dokta.oauth2.clientId={yourClientId} -Dokta.oauth2.clientSecret={yourClientSecret} -Dokta.oauth2.issuer={yourOktaIssuerUrl} 
```
