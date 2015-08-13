package xpertss.auth.tkt;




import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static xpertss.lang.Bytes.fromHexString;
import static xpertss.lang.Bytes.toHexString;

/**
 * Docs
 *    https://github.com/gavincarr/mod_auth_tkt
 *
 * 1.5 The basic format of the ticket / authentication cookie value is as follows:
 *
 *    ('+' is concatenation operation)
 *
 *    cookie := digest + hextimestamp + user_id + '!' + user_data
 *
 *    or if using tokens:
 *
 *    cookie := digest + hextimestamp + user_id + '!' + token_list + '!' + user_data
 *
 *    digest := MD5(digest0 + key)
 *
 *    digest0 := MD5(iptstamp + key + user_id + '\0' + token_list + '\0' + user_data)
 *
 *    iptstamp is a 8 bytes long byte array, bytes 0-3 are filled with client's IP address
 *      as a binary number in network byte order, bytes 4-7 are filled with timestamp as a
 *      binary number in network byte order.
 *
 *    hextimestamp is 8 character long hexadecimal number expressing timestamp used in
 *      iptstamp.
 *
 *    token_list is an optional comma-separated list of access tokens for this user. This
 *      list is checked if TKTAuthToken is set for a particular area.
 *
 *    user_data is optional
 *
 */
public class AuthTicket {

   private static final ThreadLocal<MessageDigest> digesters = new ThreadLocal<MessageDigest>() {
      protected MessageDigest initialValue() {
         try { return MessageDigest.getInstance("MD5"); } catch(NoSuchAlgorithmException e) { throw new Error("No MD% Algorithm???"); }
      }
   };


   private final byte[] checksum;
   private final long timestamp;
   private String uid;
   private String tokens;
   private String userData;



   private AuthTicket(byte[] checksum, long timestamp)
   {
      this.checksum = checksum;
      this.timestamp = timestamp;
   }


   public byte[] getChecksum()
   {
      return checksum.clone();
   }

   public long getTimestamp()
   {
      return timestamp;
   }

   public String getUsername()
   {
      return uid;
   }

   public String[] getTokens()
   {
      return (tokens != null) ? tokens.split("\\s*,\\s*") : new String[0];
   }


   public String getUserData()
   {
      return userData;
   }



   public boolean isExpired(long timeout)
   {
      long currentTime = System.currentTimeMillis() / 1000;
      return timestamp + timeout >= currentTime;
   }

   public boolean verifyChecksum(String secret, byte[] remoteAddress)
   {
      MessageDigest digester = digesters.get();
      digester.reset();

      // This stuff makes sense other than they don't specify a character
      // encoding which means this will likely break when dealing with
      // characters outside the ASCII set.
      digester.update(computeIPStamp(remoteAddress, timestamp));
      digester.update(toBytes(secret));
      digester.update(toBytes(uid));
      digester.update(new byte[1]);
      digester.update(toBytes(tokens));
      digester.update(new byte[1]);
      digester.update(toBytes(userData));

      // These retards actually created a spec where they treat the digest bytes
      // as a STRING (hex encoded no less where case matters!!!)
      digester.update(toBytes(toHexString(digester.digest()).toLowerCase()));
      byte[] digest = digester.digest(toBytes(secret));

      return Arrays.equals(checksum, digest);
   }




   public static AuthTicket parse(String ticket)
   {
      if(ticket.length() <= 40) throw new MalformedTicketException("invalid ticket length");
      AuthTicket result = parsePrefix(ticket.substring(0, 40));
      String[] parts = ticket.substring(40).split("!");
      if(parts.length == 3) {
         result.userData = parts[2].trim();
         result.tokens = parts[1].trim();
      } else if(parts.length == 2) {
         result.userData = parts[1].trim();
      } else {
         throw new MalformedTicketException("ticket missing user data");
      }
      result.uid = parts[0];
      return result;
   }

   private static AuthTicket parsePrefix(String prefix)
   {
      try {
         return new AuthTicket(fromHexString(prefix.substring(0, 32)),
                        Long.valueOf(prefix.substring(32), 16));
      } catch(NumberFormatException nfe) {
         throw new MalformedTicketException(nfe);
      }
   }





   private static byte[] computeIPStamp(byte[] remoteAddress, long timestamp)
   {
      byte[] ipStamp = new byte[8];
      if(remoteAddress != null && remoteAddress.length == 4) {
         System.arraycopy(remoteAddress, 0, ipStamp, 0, 4);
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
      return (str != null) ? str.getBytes(StandardCharsets.UTF_8) : new byte[0];
   }


}
