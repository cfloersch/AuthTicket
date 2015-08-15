package xpertss.auth.tkt;




import xpertss.lang.Bytes;
import xpertss.lang.Objects;
import xpertss.lang.Strings;
import xpertss.util.Sets;

import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;


/**
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


   private Set<String> tokens;

   private final byte[] checksum;
   private final long timestamp;
   private final String uid;
   private final String userData;
   private final String tokenData;



   private AuthTicket(byte[] checksum, long ts, String uid, String token, String data)
   {
      this.checksum = Bytes.notEmpty(checksum, "checksum");
      this.userData = Objects.notNull(data, "data");
      this.uid = Strings.notEmpty(uid, "uid");
      this.tokens = tokens(token);
      this.tokenData = token;
      this.timestamp = ts;
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

   public String getTokens()
   {
      return tokenData;
   }


   public boolean contains(String token)
   {
      return tokens.contains(token);
   }

   public boolean containsAny(Set<String> tokens)
   {
      return tokens.size() <= 0 || !Sets.intersection(this.tokens, tokens).isEmpty();
   }


   public String getUserData()
   {
      return userData;
   }



   public boolean isExpired(long timeout)
   {
      if(timeout <= 0) return false;
      long currentTime = System.currentTimeMillis() / 1000;
      return timestamp + timeout <= currentTime;
   }


   public String toString()
   {
      StringBuilder builder = new StringBuilder();
      builder.append(Strings.toLower(Bytes.toHexString(checksum)));

      byte[] ts = new byte[4];
      ts[4] = (byte) ((timestamp >>> 24) & 0xFF);
      ts[5] = (byte) ((timestamp >>> 16) & 0xFF);
      ts[6] = (byte) ((timestamp >>>  8) & 0xFF);
      ts[7] = (byte) ((timestamp) & 0xFF);
      builder.append(Strings.toLower(Bytes.toHexString(ts)));

      builder.append(uid);
      if(!Strings.isEmpty(tokenData)) {
         builder.append("!").append(tokenData);
      }
      builder.append("!").append(Strings.emptyIfNull(userData));
      return builder.toString();
   }




   public static AuthTicket create(byte[] checksum, long ts, String uid, String tokens, String data)
   {
      if(Strings.contains(uid, "!")) throw new IllegalArgumentException("uid contain invalid character: !");
      if(Strings.contains(tokens, "!")) throw new IllegalArgumentException("tokens contain invalid character: !");
      if(Strings.contains(data, "!")) throw new IllegalArgumentException("user data contain invalid character: !");
      return new AuthTicket(checksum, ts, uid, tokens, data);
   }



   private static Set<String> tokens(String string)
   {
      TreeSet<String> tokens = new TreeSet<>();
      if(!Strings.isEmpty(string)) {
         Collections.addAll(tokens, string.split("\\s*,\\s*"));
      }
      return tokens;
   }

}
