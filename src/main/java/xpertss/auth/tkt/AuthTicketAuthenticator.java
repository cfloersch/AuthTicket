package xpertss.auth.tkt;

import xpertss.lang.Objects;
import xpertss.lang.Strings;
import xpertss.net.NetUtils;
import xpertss.util.Base64;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.security.MessageDigest;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;
import static xpertss.lang.Bytes.toHexString;

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
   private final DigestAlgorithm digestAlg;

   public AuthTicketAuthenticator(String secret)
   {
      this(new AuthTicketConfig(secret));
   }

   public AuthTicketAuthenticator(AuthTicketConfig config)
   {
      this.config = Objects.notNull(config);
      this.digestAlg = config.getDigestAlgorithm();
   }


   public AuthTicket authenticate(HttpServletRequest request)
         throws TicketNotFoundException, InvalidTicketException
   {
      Cookie cookie = getCookie(request.getCookies(), config.getCookieName());
      AuthTicket ticket = digestAlg.parse(decode(cookie));

      if(ticket.isExpired(config.getTimeout())) {
         throw new ExpiredTicketException();
      }

      if(!verify(request, ticket)) {
         throw new InvalidTicketException();
      }

      if(!ticket.containsAny(config.getTokens())) {
         throw new TokenMissingException();
      }

      return ticket;
   }



   private boolean verify(HttpServletRequest request, AuthTicket ticket)
   {
      MessageDigest digester = digestAlg.digest();
      digester.reset();

      // This stuff makes sense other than they don't specify a character
      // encoding which means this will likely break when dealing with
      // characters outside the ASCII set.
      digester.update(computeIPStamp(request, ticket.getTimestamp()));
      digester.update(toBytes(config.getSecret()));
      digester.update(toBytes(ticket.getUsername()));
      digester.update(new byte[1]);
      digester.update(toBytes(ticket.getTokens()));
      digester.update(new byte[1]);
      digester.update(toBytes(ticket.getUserData()));

      // These retards actually created a spec where they treat the digest bytes
      // as a STRING (hex encoded no less where case matters!!!)
      // I think string programmers should be run out of the industry on a rail..
      digester.update(toBytes(toHexString(digester.digest()).toLowerCase()));
      byte[] digest = digester.digest(toBytes(config.getSecret()));

      return Arrays.equals(ticket.getChecksum(), digest);

   }


   private byte[] computeIPStamp(HttpServletRequest request, long timestamp)
   {
      byte[] ipStamp = new byte[8];
      if(!config.ignoreIP()) {
         String remoteIp = Strings.ifEmpty(request.getHeader("X-Forward-For"),
                                             request.getRemoteAddr());
         InetAddress remoteAddr = NetUtils.getInetAddress(remoteIp.split("\\s*,\\s*")[0]);
         if(remoteAddr == null) {
            throw new IllegalArgumentException("invalid remote ip: " + remoteIp);
         } else if(remoteAddr instanceof Inet4Address) {
            System.arraycopy(remoteAddr.getAddress(), 0, ipStamp, 0, 4);
         }
         // TODO What to do with IPv6 addresses???
         // I guess those must not have existed when this spec was created??
      }
      ipStamp[4] = (byte) ((timestamp >>> 24) & 0xFF);
      ipStamp[5] = (byte) ((timestamp >>> 16) & 0xFF);
      ipStamp[6] = (byte) ((timestamp >>>  8) & 0xFF);
      ipStamp[7] = (byte) ((timestamp) & 0xFF);

      return ipStamp;
   }





   private static byte[] toBytes(String str)
   {
      // TODO What charset do they use to convert string data into byte data
      // The C api uses unsigned characters.. Not sure what the digest algorithm does to them
      // My guess is that the C code uses ASCII (aka 8 lower bits of each char) without any real encoding
      // It doesn't make a difference here in the states where english basically translates the same
      // God help anyone that uses a more sophisticated character set.
      return (str != null) ? str.getBytes(UTF_8) : new byte[0];
   }



   private static String decode(Cookie cookie)
   {
      String str = cookie.getValue();
      // TODO Check for quotes???

      if(str.contains("!")) {
         return str;
      } else if(str.contains("%21")) {
         return NetUtils.urlDecode(str);
      } else {
         return new String(Base64.basicDecoder().decode(str));
      }
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
