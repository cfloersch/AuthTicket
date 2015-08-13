package xpertss.auth.tkt;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.util.Base64;
import java.util.Objects;

/**
 * 2.1 If no authentication cookie is present in a request a TokenMissingException is thrown.
 * <p/>
 * 2.2 If authentication cookie is present and its format is invalid a MalformedTicketException
 *     is thrown.
 * <p/>
 * 2.3 If authentication cookie is present and timeout checking is enabled, timestamp in the
 *     cookie is compared with the current time on the server. If the cookie has expired, a
 *     ExpiredTicketException is thrown.
 * <p/>
 * 2.4 If authentication cookie is present and not expired, the MD5 checksum is validated. If
 *     the MD5 checksum fails validation a InvalidTicketException is thrown.
 * <p/>
 * 2.5 If a TKTAuthToken is also required for this url/area, the user data tokens are scanned
 *     for the specified token. If the required token is not found, a TokenMissingException is
 *     thrown.
 * <p/>
 * 2.6 Upon successful authentication the AuthTicket is returned giving access to the userId,
 *     userData, and tokens.
 * <p/>
 * NOTES So it appears the mod_auth_tkt apache module will check to see if the cookie is
 * <ol>
 *    <li>Quoted - If so unquote it</li>
 *    <li>Url Encoded - Checks for the ! character in its hex encoded format - If so decode it</li>
 *    <li>Base64 encoded - Fall through if can't find ! character</li>
 * </ol>
 * It can do this because at least one '!' character must be present
 *
 */
public class AuthTicketAuthenticator {


   private final AuthTicketConfig config;

   public AuthTicketAuthenticator(String secret)
   {
      this(new AuthTicketConfig(secret));
   }

   public AuthTicketAuthenticator(AuthTicketConfig config)
   {
      this.config = Objects.requireNonNull(config);
   }


   public AuthTicket authenticate(HttpServletRequest request)
         throws TicketNotFoundException, InvalidTicketException
   {
      Cookie cookie = getCookie(request.getCookies(), config.getCookieName());
      AuthTicket ticket = AuthTicket.parse(decode(cookie)); // TODO I might not need to URLDecode this

      if(config.getTimeout() > 0 && ticket.isExpired(config.getTimeout())) {
         throw new ExpiredTicketException();
      }

      byte[] remoteAddress = computeRemoteAddress(request.getRemoteAddr());
      if(!ticket.verifyChecksum(config.getSecret(), remoteAddress)) {
         throw new InvalidTicketException();
      }

      if(!contains(ticket.getTokens(), config.getToken())) {
         throw new TokenMissingException();
      }

      return ticket;
   }



   private byte[] computeRemoteAddress(String remoteIp)
   {
      if(!config.ignoreIP()) {
         try {
            InetAddress remoteAddr = InetAddress.getByName(remoteIp);
            if(remoteAddr instanceof Inet4Address) {
               return remoteAddr.getAddress();
            }
            // TODO What to do with IPv6 address???
            // Mod_Auth_Ticket really is kids stuff..
         } catch(UnknownHostException e) { }
      }
      return new byte[4];
   }


   private static boolean contains(String[] parts, String value)
   {
      if(value == null) return true;
      for(String part : parts) {
         if(part.equals(value)) return true;
      }
      return false;
   }


   private static String decode(Cookie cookie)
   {
      String str = cookie.getValue();
      // TODO Check for quotes???

      if(str.indexOf("!") != -1) {
         return str;
      } else if(str.indexOf("%21") != -1) {
         return urlDecode(str);
      } else {
         return new String(Base64.getDecoder().decode(str));
      }
   }


   private static String urlDecode(String encoded)
   {
      try { return URLDecoder.decode(encoded, "UTF-8"); } catch(UnsupportedEncodingException e) { throw new Error("UTF-8 not supported???"); }
   }


   private static Cookie getCookie(Cookie[] cookies , String cookieName)
   {
      if(cookies != null && cookieName != null) {
         for (Cookie cookie : cookies) {
            if(cookieName.equals(cookie.getName())) return cookie;
         }
      }
      throw new TicketNotFoundException();
   }

}
