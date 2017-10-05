Okta Spring Boot Starter
========================

NOTE: current version is pending release, untill then read the docs for the [previous version](https://github.com/okta/okta-spring-security/tree/okta-spring-security-parent-0.1.0)

Okta's Spring Boot Starter will enable your Spring Boot application to work with Okta via OAuth 2.0.  Jump to our [quickstart](https://developer.okta.com/quickstart/#/angular/java/spring) to see how to configure various clients or follow along below to use curl.

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
compile 'com.okta.spring:okta-spring-security-starter'
```

## Supporting client side applications - OAuth Implicit flow

Are you writing a backend endpoints in order to support a client side application? If so follow along, otherwise skip to the next section.

### Configure your properties

You can configure your applications properties with environment variables, system properties, or configuration files. Take a look at the [Spring Boot documentation](https://docs.spring.io/spring-boot/docs/current/reference/html/boot-features-external-config.html) for more details.

| Property | Default | Details |
|----------|---------|---------|
| okta.oauth2.issuer     | N/A | [Authorization Server](/docs/how-to/set-up-auth-server.html) issuer URL, i.e.: https://{yourOktaDomain}.com/oauth2/default |
| okta.oauth2.clientId   | N/A | The Client Id of your Okta OIDC application |
| okta.oauth2.audience   | api://default | The audience of your [Authorization Server](/docs/how-to/set-up-auth-server.html) |
| okta.oauth2.scopeClaim | scp | The scope claim key in the Access Token's JWT |
| okta.oauth2.rolesClaim | groups | The claim key in the Access Token's JWT that corresponds to an array of the users groups. |

### Create a Controller

The above client makes a request to `/hello-oauth`, you simply need to create a Spring Boot application and `Controller` to handle the response: 

```java
@EnableResourceServer
@SpringBootApplication
@RestController
public class ExampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(ExampleApplication.class, args);
    }

    @GetMapping("/hello-oauth")
    public String sayHello(Principal principal) {
        return "Hello, " + principal.getName();
    }
}
```

Make sure to mark the application with Spring Security's `@EnableResourceServer` annotation, to enable handing of access tokens.

### That's it!

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

Check out a minimal example that uses the [Okta Signin Widget and JQuery](examples/siw-jquery) or [this blog post](https://developer.okta.com/blog/2017/09/19/build-a-secure-notes-application-with-kotlin-typescript-and-okta). 


## Supporting server side applications - OAuth Code flow

Building a server side application and just need to redirect to a login page? This OAuth 2.0 code flow is for you.

### Configure your properties

You can configure your applications properties with environment variables, system properties, or configuration files. Take a look at the [Spring Boot documentation](https://docs.spring.io/spring-boot/docs/current/reference/html/boot-features-external-config.html) for more details.

| Property | Required | Details |
|----------|---------|---------|
| okta.oauth2.issuer     | true | [Authorization Server](/docs/how-to/set-up-auth-server.html) issuer URL, i.e.: https://{yourOktaDomain}.com/oauth2/default |
| okta.oauth2.clientId   | true | The Client Id of your Okta OIDC application |
| okta.oauth2.clientSecret   | true | The Client Secret of your Okta OIDC application |

### Create a simple application

Create a minimal Spring Boot application:

```java
@EnableOAuth2Sso
@SpringBootApplication
@RestController
public class ExampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(ExampleApplication.class, args);
    }

    @GetMapping("/")
    public String getMessageOfTheDay(Principal principal) {
        return principal.getName() + ", this message of the day is boring";
    }
}
```

### That's it!

Open up the this link in your browser: [http://localhost:8080/](http://localhost:8080/)

You will be redirected automatically to an Okta login page. Once you successfully login, you will be redirected back to '[http://localhost:8080/](http://localhost:8080/)' and you will see the message of the day!

This module integrates with Spring Security's OAuth support, all you need is the mark your application with the standard `@EnableOAuth2Client` annotation. 

# Extra Credit

Want to build this project? 

Just clone it and run:

```bash
$ git clone https://github.com/okta/okta-spring-security.git
$ cd okta-spring-security
$ mvn install
```
