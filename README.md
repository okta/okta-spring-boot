[<img src="https://devforum.okta.com/uploads/oktadev/original/1X/bf54a16b5fda189e4ad2706fb57cbb7a1e5b8deb.png" align="right" width="256px"/>](https://devforum.okta.com/)
[![Maven Central](https://img.shields.io/maven-central/v/com.okta.spring/okta-spring-boot-starter.svg)](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.okta.spring%22%20a%3A%22okta-spring-boot-starter%22)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Support](https://img.shields.io/badge/support-Developer%20Forum-blue.svg)](https://devforum.okta.com/)

Okta Spring Boot Starter
========================

Okta's Spring Boot Starter will enable your Spring Boot application to work with Okta via OAuth 2.0/OIDC.  Jump to our [quickstart](https://developer.okta.com/quickstart/#/angular/java/spring) to see how to configure various clients or follow along below to use curl.

**NOTE:** This library works with Spring Boot 2.1+. If you need support for Spring Boot 1.5.x, use version version 0.6.

## What you need

* An Okta account (sign up for a [forever-free developer account](https://developer.okta.com/signup/))
* An OIDC application (typically a 'SPA' application)
* An [access token](https://developer.okta.com/docs/api/resources/oauth2.html)

## Include the dependency

For Apache Maven:
```xml
<dependency>
    <groupId>com.okta.spring</groupId>
    <artifactId>okta-spring-boot-starter</artifactId>
</dependency>
```

For Gradle:
```groovy
compile 'com.okta.spring:okta-spring-boot-starter'
```

## Supporting client side applications - OAuth Implicit flow

Are you writing a backend endpoints in order to support a client side application? If so follow along, otherwise skip to the next section.

### Configure your properties

You can configure your applications properties with environment variables, system properties, or configuration files. Take a look at the [Spring Boot documentation](https://docs.spring.io/spring-boot/docs/current/reference/html/boot-features-external-config.html) for more details.

| Property | Default | Details |
|----------|---------|---------|
| okta.oauth2.issuer     | N/A | [Authorization Server](/docs/how-to/set-up-auth-server.html) issuer URL, i.e.: https://{yourOktaDomain}/oauth2/default |
| okta.oauth2.clientId   | N/A | The Client Id of your Okta OIDC application |
| okta.oauth2.audience   | api://default | The audience of your [Authorization Server](/docs/how-to/set-up-auth-server.html) |
| okta.oauth2.groupsClaim | groups | The claim key in the Access Token's JWT that corresponds to an array of the users groups. |

### Create a Controller

The above client makes a request to `/hello-oauth`, you simply need to create a Spring Boot application and `Controller` to handle the response: 

```java
@RestController
@SpringBootApplication
public class ExampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(ExampleApplication.class, args);
    }

    @GetMapping("/hello-oauth")
    public String sayHello(Principal principal) {
        return "Hello, " + principal.getName();
    }
    
    @Configuration
    static class OktaOAuth2WebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests().anyRequest().authenticated()
                .and()
                .oauth2ResourceServer().jwt();
        }
    }
}
```

Make sure to configure the `WebSecurityConfigurerAdaptor` with `http.oauth2ResourceServer().jwt()` to enable handling of access tokens.

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

Check out a minimal example that uses the [Okta Signin Widget and JQuery](examples/siw-jquery) or [this blog post](https://developer.okta.com/blog/2018/11/26/spring-boot-2-dot-1-oidc-oauth2-reactive-apis). 


### Spring WebFlux

To configure a resource server when using Spring WebFlux, you need to use a couple annotations, and define a `SecurityWebFilterChain` bean.

```java
@EnableWebFluxSecurity 
@EnableReactiveMethodSecurity 
public class SecurityConfiguration {

    @Bean 
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
            .authorizeExchange()
                .anyExchange().authenticated()
                .and()
            .oauth2ResourceServer()
                .jwt();
        return http;
    }
}
```

If you want to support SSO and a resource server in the same application, you can do that too!

```java
@EnableWebFluxSecurity 
@EnableReactiveMethodSecurity 
public class SecurityConfiguration {

    @Bean 
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
            .authorizeExchange()
                .anyExchange().authenticated()
                .and()
            .oauth2Login()
                .and()
            .oauth2ResourceServer()
                .jwt();
        return http;
    }
}
```

[Full Stack Reactive with Spring WebFlux, WebSockets, and React](https://developer.okta.com/blog/2018/09/25/spring-webflux-websockets-react) uses both SSO and a resource server. Its current code uses Spring Security's OIDC support. Switching it to [use the Okta Spring Starter](https://github.com/oktadeveloper/okta-spring-webflux-react-example/pull/11) reduces the lines of code quite a bit.

## Supporting server side applications - OAuth Code flow

Building a server side application and just need to redirect to a login page? This OAuth 2.0 code flow is for you.

### Configure your properties

You can configure your applications properties with environment variables, system properties, or configuration files. Take a look at the [Spring Boot documentation](https://docs.spring.io/spring-boot/docs/current/reference/html/boot-features-external-config.html) for more details.

| Property | Required | Details |
|----------|---------|---------|
| okta.oauth2.issuer     | true | [Authorization Server](/docs/how-to/set-up-auth-server.html) issuer URL, i.e.: https://{yourOktaDomain}/oauth2/default |
| okta.oauth2.clientId   | true | The Client Id of your Okta OIDC application |
| okta.oauth2.clientSecret   | true | The Client Secret of your Okta OIDC application |

### Create a simple application

Create a minimal Spring Boot application:

```java
@RestController
@SpringBootApplication
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

If you want to allow anonymous access to specific routes you can add a `WebSecurityConfigurerAdapter`:

```java
@Configuration
static class WebConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/my-anon-page").permitAll()
                .anyRequest().authenticated()
            .and().oauth2Client()
            .and().oauth2Login();
    }
}
```

### That's it!

Open up `[http://localhost:8080/](http://localhost:8080/)` in your favorite browser. 

You'll be redirected automatically to an Okta login page. Once you successfully login, you will be redirected back to your app and you'll see the message of the day!

This module integrates with Spring Security's OAuth support, all you need is the mark your application with the standard `@EnableOAuth2Client` annotation. 

# Inject the Okta Java SDK

To integrate the [Okta Java SDK](https://github.com/okta/okta-sdk-java) into your Spring Boot application you just need to add a dependency:

```xml
<dependency>
    <groupId>com.okta.spring</groupId>
    <artifactId>okta-spring-sdk</artifactId>
</dependency>
```

Then define the `okta.client.token` property. See [creating an API token](https://developer.okta.com/docs/api/getting_started/getting_a_token) for more info.

All that is left is to inject the client (`com.okta.sdk.client.Client`)! Take a look at [this post](https://spring.io/blog/2007/07/11/setter-injection-versus-constructor-injection-and-the-use-of-required/) for more info on the best way to inject your beans.

# Extra Credit

Want to build this project? 

Just clone it and run:

```bash
$ git clone https://github.com/okta/okta-spring-boot.git
$ cd okta-spring-boot
$ mvn install
```
