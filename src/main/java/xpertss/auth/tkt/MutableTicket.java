/*
 * Copyright 2018 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 10/25/2018
 */
package xpertss.auth.tkt;

import xpertss.lang.Bytes;
import xpertss.lang.Objects;
import xpertss.lang.Strings;
import xpertss.util.Sets;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * A MutableTicket can be used to create AuthTickets. It represents the state of the
 * ticket before being encoded and as such allows tokens to be added and removed and
 * user data to be set and cleared.
 * <p>
 * <pre>
 *    {@code
 *       AuthTicketEncoder encoder = new AuthTicketEncoder(new AuthTicketConfig("our_secret"));
 *       MutableTicket ticket = new MutableTicket("jblow");
 *       ticket.addToken("admin");
 *       ticket.setUserData("Joe Blow");
 *       AuthTicket encoded = encoder.encode(null, ticket);
 *       response.setCookie(new Cookie("auth_tkt", encoded.toString()));
 *    }
 * </pre>
 * <p>
 * In the above example the resulting cookie will probably not be compliant with
 * HTTP headers and will need to be URLEncoded first.
 * <p>
 * TODO improve the example above. Possibly add equals and hashcode methods
 * <p>
 * TODO Maybe add getEncoded method that will evaluate the user data and return
 * either a BASE64 encoded token or a URLEncoded token depending on whether the
 * user data includes any binary data.. At present it can't because it is of type
 * String.
 */
public final class MutableTicket implements AuthTicket {

   private final long timestamp = System.currentTimeMillis() / 1000;
   private final Set<String> tokens = new LinkedHashSet<>();
   private final String username;

   private String userData;

   /**
    * Create a AuthTicket for the specified user id and using the current timestamp
    *
    * @param username - The user name of this ticket's principal
    */
   public MutableTicket(String username)
   {
      if(Strings.contains(username, "!")) throw new IllegalArgumentException("username contain invalid character: !");
      this.username = username;
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

   /**
    * Add a token to this ticket. The token may NOT contain the {@code !}
    * character. This method will NOT accept {@code null}.
    *
    * @param token - the token to add to this ticket.
    */
   public void addToken(String token)
   {
      if(Strings.contains(token, "!")) throw new IllegalArgumentException("token contain invalid character: !");
      tokens.add(Objects.notNull(token, "token"));
   }

   /**
    * Remove the specified token from this ticket. This will return {@code true}
    * if the specified token was present and was removed, {@code false} if the
    * token was not removed because it was not present.
    *
    * @param token - the token to remove from this ticket.
    * @return {@code true} if the token was found and removed
    */
   public boolean removeToken(String token)
   {
      return tokens.remove(token);
   }

   @Override
   public boolean contains(String token)
   {
      return tokens.contains(token);
   }

   @Override
   public boolean containsAny(Set<String> tokens)
   {
      return this.tokens.size() > 0 && !Sets.intersection(this.tokens, tokens).isEmpty();
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

   /**
    * Set an application custom data structure on this ticket. The user data can be
    * a simple string, a comma delimited string, a complex JSON structure, or just
    * about anything else you want it to be including BASE64 encoded binary data if
    * you wish.
    * <p>
    * Beware this method will not accept user data that includes the {@code !}
    * character. Also beware that AuthTickets are typically passed around as cookies
    * and this data will be subject to the HTTP header length restrictions.
    *
    * @param userData custom application user data to associate with this ticket
    */
   public void setUserData(String userData)
   {
      if(Strings.contains(userData, "!")) throw new IllegalArgumentException("user data contain invalid character: !");
      this.userData = userData;
   }



   @Override
   public byte[] getChecksum()
   {
      return new byte[0];
   }



   @Override
   public String toString()
   {
      StringBuilder builder = new StringBuilder();
      builder.append(Strings.toLower(Bytes.toHexString(new byte[4])));

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


}
