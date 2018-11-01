package xpertss.auth.tkt;

import xpertss.lang.Objects;
import xpertss.lang.Strings;


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
    * <p>
    * This includes accessing the ticket from the cookies, parsing the ticket,
    * checking expiration, verifying the ticket against the caller's IP, if
    * configured, and finally checking tokens.
    *
    * @param request The Http request
    * @return A validated AuthTicket instance associated with the request
    * @throws TicketNotFoundException if the ticket is not found
    * @throws ExpiredTicketException if the ticket is expired
    * @throws InvalidTicketException if the ticket fails verification
    * @throws TokenMissingException if the ticket is missing a required token
    * @throws MalformedTicketException if the ticket is improperly encoded
    */
   public AuthTicket authenticate(HttpServletRequest request)
         throws TicketNotFoundException, InvalidTicketException
   {
      Cookie cookie = Cookies.getCookie(request.getCookies(), config.getCookieName());
      if(cookie == null) throw new TicketNotFoundException();

      DigestAlgorithm digest = config.getDigestAlgorithm();
      AuthTicket ticket = digest.parse(cookie.getValue());

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

}
