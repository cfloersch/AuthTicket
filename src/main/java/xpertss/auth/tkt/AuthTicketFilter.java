package xpertss.auth.tkt;

import xpertss.auth.util.Time;
import xpertss.lang.Booleans;
import xpertss.proximo.Proximo;

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

import static java.util.concurrent.TimeUnit.SECONDS;
import static xpertss.proximo.Proximo.doReturn;


/**
 *
 */
public class AuthTicketFilter implements Filter {

   private AuthTicketAuthenticator authenticator;

   private URI authUri;
   private URI timeoutUri;
   private URI unauthUri;
   private boolean allowGuests;



   @Override
   public void init(FilterConfig conf)
         throws ServletException
   {
      AuthTicketConfig config = new AuthTicketConfig(conf.getInitParameter("TKTAuthSecret"));

      config.setCookieName(conf.getInitParameter("TKTAuthCookieName"));
      config.setToken(conf.getInitParameter("TKTAuthToken"));
      config.setIgnoreIP(Booleans.parse(conf.getInitParameter("TKTAuthIgnoreIP")));
      config.setTimeout(Time.parse(conf.getInitParameter("TKTAuthTimeoutURL"), SECONDS));

      authenticator = new AuthTicketAuthenticator(config);

      allowGuests = Booleans.parse(conf.getInitParameter("TKTAuthGuestLogin"));
      // TODO TKTAuthGuestCookie, TKTAuthGuestUser

      authUri = parseUri(conf.getInitParameter("TKTAuthLoginURL"), !allowGuests);
      timeoutUri = parseUri(conf.getInitParameter("TKTAuthTimeoutURL"), false);
      unauthUri = parseUri(conf.getInitParameter("TKTAuthUnauthURL"), false);

   }

   @Override
   public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
         throws IOException, ServletException
   {
      if(request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
         HttpServletRequest httpRequest = (HttpServletRequest) request;
         HttpServletResponse httpResponse = (HttpServletResponse) response;
         try {
            AuthTicket ticket = authenticator.authenticate(httpRequest);

            HttpServletRequest proxy = Proximo.proxy(HttpServletRequest.class, httpRequest);
            doReturn(ticket.getUsername()).when(proxy).getRemoteUser();
            // TODO How does the core api provide access to tokens/userData??

            chain.doFilter(proxy, response);
            return;
         } catch(ExpiredTicketException e) {
            // TODO The real auth_tkt has a method to revert user to guest if timed out
            if(timeoutUri != null) {
               httpResponse.sendRedirect(timeoutUri.toString());
               return;
            }
            // fall through
         } catch(TokenMissingException e) {
            if(unauthUri != null) {
               httpResponse.sendRedirect(unauthUri.toString());
               return;
            }
            // fall through
         } catch(Exception e) {
            // fall through
         }
         if(allowGuests) {
            // TODO Impl the guest framework
            // TODO proxy remoteUser = "guest"
            chain.doFilter(request, response);
         } else {
            httpResponse.sendRedirect(authUri.toString());
         }
      } else {
         chain.doFilter(request, response);
      }
   }

   @Override
   public void destroy()
   {
   }



   private static URI parseUri(String uri, boolean required)
   {
      try {
         return new URI(uri);
      } catch (URISyntaxException e) {
         if(required) throw new IllegalArgumentException("missing required url");
      }
      return null;
   }


}
