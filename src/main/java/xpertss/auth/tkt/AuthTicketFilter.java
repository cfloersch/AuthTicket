package xpertss.auth.tkt;

import xpertss.lang.Booleans;
import xpertss.lang.Objects;
import xpertss.lang.Strings;
import xpertss.net.NetUtils;
import xpertss.net.QueryBuilder;
import xpertss.net.UrlBuilder;
import xpertss.proximo.Answer;
import xpertss.proximo.Invocation;
import xpertss.proximo.Proximo;
import xpertss.time.Duration;
import xpertss.util.Sets;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.lang.String.format;
import static java.util.concurrent.TimeUnit.SECONDS;
import static xpertss.auth.tkt.DigestAlgorithm.*;
import static xpertss.lang.Strings.ifEmpty;
import static xpertss.proximo.Matchers.anyString;
import static xpertss.proximo.Matchers.eq;
import static xpertss.proximo.Proximo.doAnswer;
import static xpertss.proximo.Proximo.doReturn;


/**
 * AuthTicketFilter is a Java Servlet Filter implementation of the Apache auth_tkt SSO module.
 * <p/>
 * It implements a lightweight cookie-based single sign on authentication mechanism that works
 * across multiple web application servers.
 * <p/>
 * The actual authentication is done by an external service which allows authentication against
 * any source the service provider wishes. The authentication module simply encodes a ticket as
 * a cookie that this filter or the corresponding Apache module decodes and authenticates. The
 * ticket can contain authorization tokens as well as user data that can further restrict user
 * access.
 * <p/>
 * This Filter can be configured like any other Filter. It supports a number of init-params
 * <dl>
 *    <dt>TKTAuthSecret &lt;secret&gt;</dt>
 *    <dd>The secret key used for digest hashing. This should be kept secret and changed
 *        periodically and should be the same used to create the ticket. The longer the
 *        better. e.g.
 *        <p/>
 *        <pre>TKTAuthSecret  m2z#b&&2hd5zFev-b=Ham9_!=R74y-F44x&a6BnPEK!kQ&qz</pre>
 *    </dd>
 *
 *    <dt>TKTAuthDigestType [ MD5 | SHA256 | SHA512 ]</dt>
 *    <dd>One of MD5 | SHA256 | SHA512 . The digest/hash type to use in tickets. The default
 *        is MD5 , which is faster, but has now been shown to be vulnerable to collision
 *        attacks. Such attacks are not directly applicable to AuthTicketFilter, which
 *        primarily relies on the security of the shared secret rather than the strength of
 *        the hashing scheme. More paranoid users will probably prefer to use one of the SHA
 *        digest types, however.
 *        <p/>
 *        The default is likely to change in a future version, so setting the digest type
 *        explicitly is encouraged.
 *        <p/>
 *        <pre>TKTAuthDigestType MD5</pre>
 *    </dd>
 *
 *    <dt>TKTAuthLoginURL &lt;url&gt;</dt>
 *    <dd>Standard URL to which unauthenticated users are redirected. This is a required
 *        directive. e.g.
 *        <p/>
 *        <pre>TKTAuthLoginURL https://www.example.com/auth/login.cgi</pre>
 *    </dd>
 *
 *    <dt>TKTAuthTimeoutURL &lt;url&gt;</dt>
 *    <dd>URL to which users are redirected in the event their ticket times out. Default:
 *        TKTAuthLoginURL. e.g.
 *        <p/>
 *        <pre>TKTAuthTimeoutURL https://www.example.com/auth/login.cgi?timeout=1</pre>
 *    </dd>
 *
 *    <dt>TKTAuthPostTimeoutURL  &lt;url&gt;</dt>
 *    <dd>URL to which users are redirected in the event their ticket times out during a
 *        POST operation. This case is distinguished to allow you to handle such cases
 *        specially - you probably don't want to redirect back to the referrer after login,
 *        for instance. Default: TKTAuthTimeoutURL. e.g.
 *        <p/>
 *        <pre>TKTAuthPostTimeoutURL https://www.example.com/auth/login.cgi?timeout=2</pre>
 *    </dd>
 *
 *    <dt>TKTAuthUnauthURL  &lt;url&gt;</dt>
 *    <dd>URL to which users are redirected in the event that they are not authorised for a
 *        particular area e.g. incorrect tokens.
 *        <p/>
 *        <pre>TKTAuthUnauthURL https://www.example.com/auth/login.cgi?unauth=1</pre>
 *    </dd>
 *
 *    <dt>TKTAuthGuestLogin &lt;boolean&gt;</dt>
 *    <dd>Flag to turn on 'guest' mode, which means that any user without a valid ticket is
 *        authenticated anyway as a 'guest' user. This is useful for allowing public access
 *        for guests and robots, while allowing more personalised or privileged access for
 *        users who login. Default: off. e.g.
 *        <p/>
 *        <pre>TKTAuthGuestLogin on</pre>
 *    </dd>
 *
 *    <dt>TKTAuthGuestFallback &lt;boolean&gt;</dt>
 *    <dd>Flag to indicate that a timed out user ticket should automatically fallback to
 *        'guest' status instead of redirecting to the TKTAuthTimeoutURL. Only makes sense
 *        with TKTAuthGuestLogin on, of course. Default: off. e.g.
 *        <p/>
 *        <pre>TKTAuthGuestFallback on</pre>
 *    </dd>
 *
 *    <dt>TKTAuthTimeout &lt;time&gt;</dt>
 *    <dd>The ticket timeout period. After this period, the ticket is considered stale,
 *        and the user is redirected to the TKTAuthTimeoutURL (if set, else to the
 *        TKTAuthLoginURL).
 *        <p/>
 *        The following units can also be specified on the timeout (with no spaces between
 *        timeout and unit): d/days, h/hours, m/minutes, and s/seconds. It defaults to
 *        seconds if a unit is not specified.
 *        <p/>
 *        Setting TKTAuthTimeout to 0 means never timeout, but this is strongly discouraged,
 *        as it allows for trivial replay attacks.
 *        <p/>
 *        Default: 2h. Examples:
 *        <p/>
 *        <pre>
 *           TKTAuthTimeout 86400
 *           TKTAuthTimeout 86400s
 *           TKTAuthTimeout 1440m
 *           TKTAuthTimeout 24h
 *           TKTAuthTimeout 1d
 *        </pre>
 *    </dd>
 *
 *    <dt>TKTAuthCookieName &lt;name&gt;</dt>
 *    <dd>The name used for the ticket cookie. Default: 'auth_tkt'.
 *        <p/>
 *        <pre>TKTAuthCookieName MyCookieName</pre>
 *    </dd>
 *
 *    <dt>TKTAuthBackArgName  &lt;url&gt;</dt>
 *    <dd>The name used for the back GET parameter. If this is set, AuthTicketFilter will add
 *        a GET parameter to all redirect URLs containing a URI-escaped version of the current
 *        requested page e.g. if the requested page is http://www.example.com/index.html and
 *        TKTAuthBackArgName is set to 'back', AuthTicketFilter will add a parameter like:
 *        <p/>
 *        <pre>back=http%3A%2F%2Fwww.example.com%2Findex.html</pre>
 *        <p/>
 *        to the TKTAuthLoginURL it redirects to, allowing your login script to redirect back
 *        to the requested page upon successful login. Default: 'back'.
 *        <p/>
 *        <pre>TKTAuthBackArgName previous</pre>
 *    </dd>
 *
 *    <dt>TKTAuthToken &lt;token&gt;</dt>
 *    <dd>Comma delimited list indicating a required token for the given location, implementing
 *        a simple form of token-based access control. If the user's ticket does not contain one
 *        or more of the required tokens in the ticket token list then authTicketFilter will
 *        redirect to the TKTAuthUnauthURL location (or TKTAuthLoginURL if not set). Your login
 *        script is expected to set the appropriate token list up at login time, of course.
 *        Default: none. e.g.
 *        <p/>
 *        <pre>TKTAuthToken  finance,admin</pre>
 *    </dd>
 *
 *    <dt>TKTAuthIgnoreIP  &lt;boolean&gt;</dt>
 *    <dd>Flag indicating that AuthTicketFilter should ignore the client IP address in
 *        authenticating tickets (your login script must support this as well, setting the
 *        client IP address to 0.0.0.0). This is often required out on the open internet,
 *        especially if you are using an HTTPS login page (as you should) and are dealing
 *        with more than a handful of users (the typical problem being transparent HTTP
 *        proxies at ISPs). Default: 'off' i.e. ticket is only valid from the originating
 *        IP address. e.g.
 *        <p/>
 *        <pre>TKTAuthIgnoreIP on</pre>
 *    </dd>
 * </dl>
 * <p/>
 * This implementation does not support setting cookies on the user's browser. As a result a
 * number of init parameters are not supported:
 * <ul>
 *    <li>TKTAuthTimeoutRefresh</li>
 *    <li>TKTAuthGuestCookie</li>
 *    <li>TKTAuthBackCookieName</li>
 *    <li>TKTAuthDomain</li>
 *    <li>TKTAuthCookieExpires</li>
 *    <li>TKTAuthCookieSecure</li>
 * </ul>
 * Additionally, this implementation does not support tracking guest user sessions via UUID
 * formatting. As a result the TKTAuthGuestUser init parameter is ignored.
 * <p/>
 * Calls to {@link HttpServletRequest#isUserInRole(String)} will return {@code true} if the
 * specified role exists in the ticket's token set, {@code false} otherwise.
 * <p/>
 * Access to the userId is provided via a call to {@link HttpServletRequest#getRemoteUser()}.
 * <p/>
 * Access to the UserData can be retrieved from the request attribute <tt>TKTAuthUserData</tt>.
 * <p/>
 * {@link HttpServletRequest#getAuthType()} will return <B>AUTH_TKT</B>
 */
public class AuthTicketFilter implements Filter {

/*
 * Source
 *    https://github.com/gavincarr/mod_auth_tkt
 * Man Page
 *    http://linux.die.net/man/3/mod_auth_tkt
 */

   private AuthTicketAuthenticator authenticator;

   private URI authUri;
   private URI timeoutUri;
   private URI unauthUri;
   private URI postUri;
   private String backArgName;
   private boolean allowGuests;
   private boolean guestFallback;

   private Pattern pattern;

   @Override
   public void init(FilterConfig conf)
         throws ServletException
   {
      AuthTicketConfig config = new AuthTicketConfig(conf.getInitParameter("TKTAuthSecret"));

      config.setIgnoreIP(Booleans.parse(conf.getInitParameter("TKTAuthIgnoreIP")));

      if(!Strings.isEmpty(conf.getInitParameter("TKTAuthTimeout"))) {
         config.setTimeout(Duration.parse(conf.getInitParameter("TKTAuthTimeout"), SECONDS));
      }

      if(!Strings.isEmpty(conf.getInitParameter("TKTAuthCookieName"))) {
         config.setCookieName(conf.getInitParameter("TKTAuthCookieName"));
      }

      if(!Strings.isEmpty(conf.getInitParameter("TKTAuthToken"))) {
         config.setTokens(Sets.of(conf.getInitParameter("TKTAuthToken").split("\\s*,\\s*")));
      }

      if(!Strings.isEmpty(conf.getInitParameter("TKTAuthDigestType"))) {
         config.setDigestAlgorithm(valueOf(conf.getInitParameter("TKTAuthDigestType")));
      }


      authenticator = new AuthTicketAuthenticator(config);

      allowGuests = Booleans.parse(conf.getInitParameter("TKTAuthGuestLogin"));
      guestFallback = Booleans.parse(conf.getInitParameter("TKTAuthGuestFallback"));

      backArgName = ifEmpty(conf.getInitParameter("TKTAuthBackArgName"), "back");

      pattern = Pattern.compile(ifEmpty(conf.getInitParameter("TKTUrlPattern"), "^/.*"));

      authUri = parseUri(conf.getInitParameter("TKTAuthLoginURL"), true);
      timeoutUri = parseUri(conf.getInitParameter("TKTAuthTimeoutURL"), false);
      unauthUri = parseUri(conf.getInitParameter("TKTAuthUnauthURL"), false);
      postUri = parseUri(conf.getInitParameter("TKTAuthPostTimeoutURL"), false);

   }

   @Override
   public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
         throws IOException, ServletException
   {
      if(request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
         HttpServletRequest httpRequest = (HttpServletRequest) request;
         HttpServletResponse httpResponse = (HttpServletResponse) response;
         Matcher matcher = pattern.matcher(httpRequest.getRequestURI());
         if(matcher.matches()) {
            try {
               final AuthTicket ticket = authenticator.authenticate(httpRequest);
               HttpServletRequest proxy = Proximo.proxy(HttpServletRequest.class, httpRequest);
               doReturn("AUTH_TKT").when(proxy).getAuthType(); // Apache module returns Basic
               doReturn(ticket.getUsername()).when(proxy).getRemoteUser();
               doAnswer(new Answer<Boolean>() {
                  @Override
                  public Boolean answer(Invocation invocation)
                        throws Throwable {
                     return ticket.contains(invocation.getArgumentAt(0, String.class));
                  }
               }).when(proxy).isUserInRole(anyString());
               doReturn(ticket.getUserData()).when(proxy).getAttribute(eq("TKTAuthUserData"));
               chain.doFilter(proxy, response);
            } catch (ExpiredTicketException e) {
               if (guestFallback && allowGuests) {
                  processFailure(httpRequest, httpResponse, chain);
               } else if (postUri != null && httpRequest.getMethod().equals("POST")) {
                  httpResponse.sendRedirect(formatUrl(httpRequest, postUri));
               } else if (timeoutUri != null) {
                  httpResponse.sendRedirect(formatUrl(httpRequest, timeoutUri));
               } else {
                  httpResponse.sendRedirect(formatUrl(httpRequest, authUri));
               }
            } catch (TokenMissingException e) {
               if (unauthUri != null) {
                  httpResponse.sendRedirect(formatUrl(httpRequest, unauthUri));
               } else {
                  httpResponse.sendRedirect(formatUrl(httpRequest, authUri));
               }
            } catch (Exception e) {
               processFailure(httpRequest, httpResponse, chain);
            }
         } else {
            chain.doFilter(request, response);
         }
      } else {
         throw new ServletException("Only supports http");
      }
   }

   @Override
   public void destroy()
   {
   }

   private void processFailure(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws IOException, ServletException
   {
      if(allowGuests) {
         HttpServletRequest proxy = Proximo.proxy(HttpServletRequest.class, request);
         doReturn("guest").when(proxy).getRemoteUser();
         doReturn("AUTH_TKT").when(proxy).getAuthType(); // Apache module returns Basic
         doReturn(false).when(proxy).isUserInRole(anyString());
         chain.doFilter(proxy, response);
      } else {
         response.sendRedirect(formatUrl(request, authUri));
      }
   }


   private String formatUrl(HttpServletRequest request, URI target)
   {
      QueryBuilder query = QueryBuilder.create(target.getQuery());
      query.add(backArgName, currentRequestUri(request));
      return UrlBuilder.create(target).setQuery(query.build()).build();
   }

   private static String currentRequestUri(HttpServletRequest request)
   {
      if(request.getHeader("X-Back-Url") != null) return request.getHeader("X-Back-Url");

      String scheme = ifEmpty(request.getHeader("X-Forwarded-Proto"), request.getScheme());

      UrlBuilder builder = UrlBuilder.create(scheme);
      String host = ifEmpty(request.getHeader("X-Forwarded-Host"), request.getHeader("Host"));

      if(host.contains(":")) {
         int idx = host.indexOf(":");
         builder.setHost(host.substring(0, idx));
         builder.setPort(Integer.parseInt(host.substring(idx+1)));
      } else {
         builder.setHost(host);
      }

      builder.setPath(request.getRequestURI());
      builder.setQuery(request.getQueryString());

      return NetUtils.urlEncode(builder.build());
   }

   private static URI parseUri(String uri, boolean required)
      throws IllegalArgumentException
   {
      if(!Strings.isEmpty(uri)) {
         try {
            URI result = new URI(uri);
            if(Objects.isOneOf(Strings.toLower(result.getScheme()), "https", "http")) {
               return result;
            } else {
               throw new IllegalArgumentException(format("did not expect %s url", result.getScheme()));
            }
         } catch(URISyntaxException e) {
            throw new IllegalArgumentException("malformed url", e);
         }
      }
      if(required) throw new IllegalArgumentException("missing required url");
      return null;
   }



}
