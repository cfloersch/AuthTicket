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
      <param-value>"^/simulcast/(?!pub/).*\.do.*</param-value>
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