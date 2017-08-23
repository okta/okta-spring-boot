Okta Spring Boot Starter
========================

Okta's Spring Boot Starter will enable your Spring Boot application to work with an Okta access token via an OAuth implicit flow.  Jump to our [quickstart](https://developer.okta.com/quickstart/#/angular/java/spring) to see how to configure various clients or follow along below to use curl.

## What you need

* An Okta account (sign up for a [forever-free developer account](https://developer.okta.com/signup/))
* An OIDC application (typically a 'SPA' application)
* An [access token](https://developer.okta.com/docs/api/resources/oauth2.html)

## Include the dependency

For Apache Maven:
```xml
<dependency>
    <groupId>com.okta.spring</groupId>
    <artifactId>okta-spring-security-starter</artifactId>
</dependency>
```

For Gradle:
```groovy
compile 'com.okta.spring:okta-spring-security-starter:{{ site.versions.spring_security_starter }}'
```

## Configure your properties

You can configure your applications properties with environment variables, system properties, or configuration files. Take a look at the [Spring Boot documentation](https://docs.spring.io/spring-boot/docs/current/reference/html/boot-features-external-config.html) for more details.

| Property | Default | Details |
|----------|---------|---------|
| okta.oauth.issuer     | N/A | [Authorization Server](/docs/how-to/set-up-auth-server.html) issuer URL, i.e.: https://{yourOktaDomain}.com/oauth2/default |
| okta.oauth.clientId   | N/A | The Client Id of your Okta OIDC application |
| okta.oauth.audience   | api://default | The audience of your [Authorization Server](/docs/how-to/set-up-auth-server.html) |
| okta.oauth.scopeClaim | scp | The scope claim key in the Access Token's JWT |
| okta.oauth.rolesClaim | groups | The claim key in the Access Token's JWT that corresponds to an array of the users groups. |

## Create a Controller 

The above client makes a request to `/hello-oauth`, you simply need to create a `Controller` to handle the response: 

```java
@RestController
class ExampleRestController {

    @GetMapping("/hello-oauth")
    public String sayHello(Principal principal) {
        return "Hello, " + principal.getName();
    }
}
```

## That's it!

To test things out you can use curl:

```bash
$ curl http://localhost:8080/hello-oauth \
   --header "Authorization: Bearer ${accessToken}"
```
The result should look something like:
```text
Hello, joe.coder@example.com
```

Okta's Spring Security integration will [parse the JWT access token](https://developer.okta.com/blog/2017/06/21/what-the-heck-is-oauth#oauth-flows) from the HTTP request's `Authorization: Bearer` header value.

Check out a minimal example that uses the [Okta Signin Widget and JQuery](examples/siw-jquery) or [this blog post](https://scotch.io/tutorials/build-a-secure-notes-application-with-kotlin-typescript-and-okta). 


# Extra Credit

Want to build this project? 

Just clone it and run:

```bash
$ git clone https://github.com/okta/okta-spring-security.git
$ cd okta-spring-security
$ mvn install
```

