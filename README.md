# AuthTicket
Java Servlet Filter implementation of the Apache mod_auth_tkt SSO

Simple Usage:
```
<filter>
   <filter-name>AuthTicket</filter-name>
   <filter-class>xpertss.auth.tkt.AuthTicketFilter</filter-class>
   <init-param>
      <param-name>TKTAuthSecret</param-name>
      <param-value>some_random_secret_key</param-value>
   </init-param>
   <init-param>
      <param-name>TKTUrlPattern</param-name>
      <param-value>^/simulcast/(?!pub/).*\.do.*</param-value>
   </init-param>
   <init-param>
      <param-name>TKTAuthLoginURL</param-name>
      <param-value>https://www.example.com/login?type=1</param-value>
   </init-param>
   <init-param>
      <param-name>TKTAuthIgnoreIP</param-name>
      <param-value>on</param-value>
   </init-param>
</filter>
```
The TKTUrlPattern is an optional value that can be any valid regular expression
based pattern that when matched will result in the AuthTicket being evaluated.
This is needed because the servlet specification does not provide a very capable
filter mapping mechanism. If it is omitted then every path that matches the
filter's url pattern defined below will match.

Then you'll need to map the filter like:
```
<filter-mapping>
   <filter-name>AuthTicket</filter-name>
   <url-pattern>/*</url-pattern>
</filter-mapping>
```

The combination of filter mapping and TXTUrlPattern should give you a great deal
of power when determining which paths should be filtered and which should not.

##Web 2.0 Ajax Calls

To enable support for JQuery based ajax calls the X-Back-Url header may be passed as
part of the request to specify an alternative back url to use from the current request.
This ensures ModAuthTKT remains useful in the web 2.0 world where UI and Data are no
longer bound together.

```
    $.ajaxSetup({
        headers: { 'X-Back-Url': window.location.href },
        error: function (x, status, error) {
            if (x.status == 403) {
                window.location.href=x.getResponseHeader('Location');
            } else {
                alert("An error occurred: " + status + "nError: " + error);
            }
        }
    });
```
The X-Back-Url should be escaped if there is any possibility that its contents could
not be used as a url query parameter.

Because JQuery attempts to auto-follow 307 redirects this filter will respond with a
403 Forbidden response code rather than a 307 if the X-Back-Url is specified. This
will allow application developers to code their own handler for this response code
which can redirect the main document location.

The response will include a Location header regardless of its status 307 or 403.

To enable the client's ability to access the Location header for a CORS requests the
server must include the header

```
Access-Control-Expose-Headers: Location
```

Additionally, to set a X-Back-Url header the server must respond with a CORS header

```
Access-Control-Allow-Headers: x-requested-with, Content-Type, X-Back-Url
```

Programmatically
----------------

This code can also be used to programmatically parse or validate Auth Tickets.

```java
   AuthTicketConfig config = new AuthTicketConfig("our_secret");
   Cookie cookie = Cookies.getCookie(request.getCookies(), config.getCookieName());
   AuthTicketAuthenticator authenticator = new AuthTicketAuthenticator(config);
   String authTktStr = AuthTicketAuthenticator.decode(cookie);
   AuthTicket ticket = config.getDigestAlgorithm().parse(authTktStr);
   if(!authenticator.verify(request.getRemoteAddr(), ticket)) {
      throw new ForbiddenException();
   }
```

Obviously, the above is simplified. The logic necessary to obtain the remote
address is often more complex. The decoding step above strips and quoting,
URL encoding, or Base64 encoding that may be applied to the cookie and returns
a string.

There are also a number of RuntimeExceptions that the above code can throw that
you may wish to catch and deal with.

In many cases we don't actually need to verify the auth ticket but we would like
to access fields from within the auth ticket.

```java
   DigestAlgorithm digest = DigestAlgorithm.MD5;
   AuthTicket ticket = digest.parse(authTktStr);
   String remoteUser = ticket.getUsername();
   String userData = ticket.getUserData();
```

In the above example we skip the configuration step and jump straight to our
desired digest algorithm. We can use that digest to parse the auth ticket string
into an AuthTicket instance.
