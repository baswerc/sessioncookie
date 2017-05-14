SessionCookie
======

SessionCookie is a Java library for storing Servlet based HttpSession objects as a cookie stored in the client browser. 

## Getting Started

### Direct Download
You can download <a href="https://github.com/baswerc/sessioncookie/releases/download/v1.0.0-beta/sessioncookie-1.0.0-beta.jar">sessioncookie-1.0.0-beta.jar</a> directly and place in your project.

### Using Maven
Add the following dependency into your Maven project:

````xml
<dependency>
    <groupId>org.baswell</groupId>
    <artifactId>sessioncookie</artifactId>
    <version>1.0.0-beta</version>
</dependency>
````
### Dependencies
SessionCookie runs within a Java Servlet container at API 3.0 or higher and a JVM at 1.7 or higher. SessionCookie has no other external dependencies.

## Servlet Container Configuration

The <a href="https://baswerc.github.io/sessioncookie/org/baswell/sessioncookie/SessionCookieFilter.html">SessionCookieFilter</a> should be added as the first filter in your application.

````xml
<filter>
    <filter-name>SessionCookieFilter</filter-name>
    <filter-class>org.baswell.sessioncookie.SessionCookieFilter</filter-class>
</filter>
<filter-mapping>
    <filter-name>SessionCookieFilter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
````

This filter should be placed in front of all HTTP request that use <a href="http://docs.oracle.com/javaee/7/api/javax/servlet/http/HttpSession.html">HttpSession</a>. In addition to the `filter-mapping` configuration, you can control which HTTP requests are candidates for routes with the `ONLY` and `EXCEPT` filter parameters
(this can improve performance when it's known that certain HTTP paths won't map to routes). Once the filter is in place all HttpSession objects will be backed by cookies.

## Potential Problems
The following are reasons you might not want to use SessionCookie.

* You can only store about 4kb of data in a cookie. If your encoded and encrypted sessions are larger then this then this library will not work for your needs.
* Session cookies are sent along with every request made to your server . This increases the size of the request and response Big cookies mean bigger requests and responses, which mean slower websites.
* If you accidentally expose your secret_key_base, your users can change the data you’ve put inside your cookie. When this includes things like current_user_id, anyone can become whichever user they want!
