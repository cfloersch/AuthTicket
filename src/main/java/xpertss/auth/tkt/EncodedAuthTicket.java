package xpertss.auth.tkt;




import xpertss.lang.Bytes;
import xpertss.lang.Objects;
import xpertss.lang.Strings;
import xpertss.net.NetUtils;
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
final class EncodedAuthTicket implements AuthTicket {

   private final long timestamp;
   private final String username;
   private final String userData;
   private final byte[] checksum;
   private final Set<String> tokens;


   private EncodedAuthTicket(byte[] checksum, long ts, String username, Set<String> tokens, String data)
   {
      this.userData = Objects.notNull(data, "data");
      this.username = Strings.notEmpty(username, "username");
      this.tokens = tokens;
      this.timestamp = ts;
      this.checksum = Bytes.notEmpty(checksum, "checksum");
   }

   @Override
   public String getUsername()
   {
      return username;
   }


   
   @Override
   public Set<String> getTokens()
   {
      return Collections.unmodifiableSet(tokens);
   }

   @Override
   public boolean contains(String token)
   {
      return tokens.contains(token);
   }

   @Override
   public boolean containsAny(Set<String> tokens)
   {
      return tokens.size() <= 0 || !Sets.intersection(this.tokens, tokens).isEmpty();
   }



   @Override
   public long getTimestamp()
   {
      return timestamp;
   }

   @Override
   public boolean isExpired(long timeout)
   {
      if(timeout <= 0) return false;
      long currentTime = System.currentTimeMillis() / 1000;
      return timestamp + timeout <= currentTime;
   }



   @Override
   public String getUserData()
   {
      return userData;
   }



   @Override
   public byte[] getChecksum()
   {
      return (checksum == null) ? new byte[4] : checksum.clone();
   }




   @Override
   public boolean equals(Object obj)
   {
      if(obj instanceof EncodedAuthTicket) {
         EncodedAuthTicket o = (EncodedAuthTicket) obj;
         return Objects.equal(toString(), o.toString());
      }
      return false;
   }

   @Override
   public int hashCode()
   {
      return Objects.hash(timestamp, username, tokens, userData);
   }


   @Override
   public String toString()
   {
      StringBuilder builder = new StringBuilder();
      builder.append(Strings.toLower(Bytes.toHexString(getChecksum())));

      byte[] ts = new byte[4];
      ts[0] = (byte) ((timestamp >>> 24) & 0xFF);
      ts[1] = (byte) ((timestamp >>> 16) & 0xFF);
      ts[2] = (byte) ((timestamp >>>  8) & 0xFF);
      ts[3] = (byte) ((timestamp) & 0xFF);
      builder.append(Strings.toLower(Bytes.toHexString(ts)));

      builder.append(username);
      if(!tokens.isEmpty()) {
         builder.append("!").append(Strings.join(",", tokens));
      }
      builder.append("!").append(Strings.emptyIfNull(userData));
      return builder.toString();
   }

   @Override
   public String getEncoded()
   {
      return NetUtils.urlEncode(toString());
   }


   
   static EncodedAuthTicket create(byte[] checksum, long ts, String uid, String tokenData, String data)
   {
      return new EncodedAuthTicket(checksum, ts, uid, tokens(tokenData), data);
   }

   static EncodedAuthTicket create(AuthTicket ticket, byte[] checksum)
   {
      return new EncodedAuthTicket(checksum, ticket.getTimestamp(), ticket.getUsername(), ticket.getTokens(), ticket.getUserData());
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
