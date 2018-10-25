package xpertss.auth.tkt;

import xpertss.lang.Objects;
import xpertss.lang.Strings;
import xpertss.net.NetUtils;
import xpertss.util.Base64;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;


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
public final class AuthTicketAuthenticator {

   private final AuthTicketConfig config;
   private final AuthTicketEncoder encoder;

   public AuthTicketAuthenticator(String secret)
   {
      this(new AuthTicketConfig(secret));
   }

   public AuthTicketAuthenticator(AuthTicketConfig config)
   {
      this.config = Objects.notNull(config);
      this.encoder = new AuthTicketEncoder(config);
   }


   /**
    * Complete implementation of the HttpServlet authentication algorithm.
    *
    * @param request The Http request
    * @return A validated AuthTicket instance associated with the request
    * @throws TicketNotFoundException if the ticket is not found or is expired
    * @throws InvalidTicketException if the ticket is invalid or missing a required token
    */
   public AuthTicket authenticate(HttpServletRequest request)
         throws TicketNotFoundException, InvalidTicketException
   {
      Cookie cookie = Cookies.getCookie(request.getCookies(), config.getCookieName());
      if(cookie == null) throw new TicketNotFoundException();

      AuthTicket ticket = parse(cookie);

      if(ticket.isExpired(config.getTimeout())) {
         throw new ExpiredTicketException();
      }

      String remoteIp = Strings.ifEmpty(request.getHeader("X-Forward-For"),
                                          request.getRemoteAddr());

      if(!verify(remoteIp, ticket)) {
         throw new InvalidTicketException();
      }

      if(!ticket.containsAny(config.getTokens())) {
         throw new TokenMissingException();
      }

      return ticket;
   }


   /**
    * This will parse a Cookie into an AuthTicket using the current configuration.
    * It will NOT validate the auth ticket.
    * <p/>
    * This will attempt to unquote, url decode, or base64 decode the cookie text
    * before parsing it into an AuthTicket instance.
    *
    * @param cookie The Http Cookie to parse
    * @return An AuthTicket instance representing the cookie data
    * @throws MalformedTicketException if the cookie is not a properly structured auth ticket
    * @throws NullPointerException if the supplied cookie is null
    */
   public AuthTicket parse(Cookie cookie) throws MalformedTicketException
   {
      return config.getDigestAlgorithm().parse(decode(cookie));
   }


   /**
    * Verify a given AuthTicket (and its optional IP).
    * <p/>
    * The supplied remote IP can be null if the authenticator is not
    * configured to validate IP. You can also always submit "0.0.0.0"
    * which has the same effect as disabling IP validation.
    *
    * @param remoteIp Optional remote IP of the calling client
    * @param ticket The previously decoded Auth Ticket to validate
    * @return true if the auth ticket can be verified, false otherwise.
    */
   public boolean verify(String remoteIp, AuthTicket ticket)
   {
      AuthTicket encoded = encoder.encode(remoteIp, ticket);
      return Arrays.equals(ticket.getChecksum(), encoded.getChecksum());
   }





   private static String decode(Cookie cookie)
   {
      String str = Strings.unquote(cookie.getValue());

      if(str.contains("!")) {
         return str;
      } else if(str.contains("%21")) {
         return NetUtils.urlDecode(str);
      } else {
         return new String(Base64.basicDecoder().decode(str));
      }
   }





}
