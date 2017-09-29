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
cd examples/hosted-login-code-flow
```

Run the example:
```bash
mvn spring-boot:run -Dokta.client.clientId={yourClientId} -Dokta.client.clientSecret={yourClientSecret} -Dokta.issuer={yourOktaIssuerUrl} 
```
