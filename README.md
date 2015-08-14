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
      <param-name>TKTAuthLoginURL</param-name>
      <param-value>https://www.example.com/login?type=1</param-value>
   </init-param>
   <init-param>
      <param-name>TKTAuthIgnoreIP</param-name>
      <param-value>on</param-value>
   </init-param>
</filter>
```

Then you'll need to map the filter to a path like:
```
<servlet-mapping>
   <servlet-name>AuthTicket</servlet-name>
   <url-pattern>/simulcast/*.do</url-pattern>
</servlet-mapping>
```