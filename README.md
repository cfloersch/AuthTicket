# AuthTicket
Java Servlet Filter implementation of the Apache mod_auth_tkt SSO


Maven Central Repository

```xml
<dependency>
    <groupId>org.xpertss</groupId>
    <artifactId>auth-tkt</artifactId>
    <version>2.0.0</version>
</dependency>
```


Simple Usage:
```xml
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


Accessing Auth Ticket Data
--------------------------

The filter will parse the Auth Ticket's properties which include username, tokens,
and user data and make it available via the HttpServletRequest. They can be accessed
as follows:

```
if("AUTH_TKT".equals(request.getAuthType())) {
   String username = request.getRemoteUser();
   String userdata = request.getAttribute("TKTAuthUserData");
   if(request.isUserInRole("mytoken")) {
      ... do something
   }
}
```

When the request was authenticated using this Auth Ticket filter the auth type will
always be `AUTH_TKT` as opposed to Basic or Digest. The username can be accessed via
the get remote user method. Tokens are treated as roles and can be queried but not
retrieved using the is user in role method. Finally, the user data can be retrieved
from the request attributes.


Web 2.0 Ajax Calls
------------------

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


Programmatic Verification
-------------------------

This code can also be used to programmatically parse or validate Auth Tickets.

```java
   AuthTicketConfig config = new AuthTicketConfig("our_secret");
   Cookie cookie = Cookies.getCookie(request.getCookies(), config.getCookieName());
   AuthTicketAuthenticator authenticator = new AuthTicketAuthenticator(config);
   AuthTicket ticket = config.getDigestAlgorithm().parse(cookie);
   if(!authenticator.verify(request.getRemoteAddr(), ticket)) {
      throw new ForbiddenException();
   }
   String remoteUser = ticket.getUsername();
   String userData = ticket.getUserData();
```

Obviously, the above is simplified. The logic necessary to obtain the remote
address is often more complex and we are not checking tokens nor expiration.

There are also a number of RuntimeExceptions that the above code can throw that
you may wish to catch and deal with.


Creating Auth Tickets
---------------------

```java
   AuthTicketConfig config = new AuthTicketConfig("our_secret");
   AuthTicketEncoder encoder = new AuthTicketEncoder(config);
   String username = request.getParameter("username");
   String password = request.getParameter("password");
   if(myAuthMechanism.validate(username, password)) {
      MutableAuthTicket ticket = new MutableAuthTicket(username);
      for(String role : rolesFor(username)) {
         ticket.addToken(role);
      }
      ticket.setUserData(getAuthorizations(username).toJson());
      AuthTicket encoded = encoder.encode(null, ticket);
      Cookie cookie = new Cookie(config.getCookieName(),
                                 encoded.getEncoded());
      response.addCookie(cookie);
      httpResponse.sendRedirect(request.getParameter("back"));
   }
```

The above is a very basic example of implementing a login service which creates
an AuthTicket that can be returned to the user's browser as a Cookie. Obviously,
you'll want to be more discriminating as to what domains and security levels the
cookie is configured for and you'll need more error handling code.