/*
 * Copyright 2018 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 10/25/2018
 */
package xpertss.auth.tkt;

import java.util.Set;

public interface AuthTicket {

   /**
    * Returns the username of the authenticated principal.
    *
    * @return the username of the authenticated principal
    */
   public String getUsername();

   /**
    * Returns the timestamp measured in seconds since EPOCH when this
    * ticket was created. It will be encoded within the ticket and can
    * be used to expire the ticket.
    *
    * @return the ticket creation timestamp in seconds since EPOCH.
    */
   public long getTimestamp();

   /**
    * Returns {@code true} if this ticket is expired based on the specified
    * timeout in seconds.
    *
    * @param timeout The number of seconds the ticket should be considered valid
    * @return {@code true} if the ticket is expired, {@code false} otherwise
    */
   public boolean isExpired(long timeout);


   /**
    * Returns an immutable set of tokens associated with this ticket. Tokens
    * are most often used as roles or scopes that can be used to limit access
    * to certain parts of a web site or functionality within an application.
    *
    * @return an immutable set of tokens associated with this ticket.
    */
   public Set<String> getTokens();

   /**
    * Returns {@code true} if this ticket contains the specified token.
    *
    * @param token - the token to check
    * @return {@code true} if this ticket contains the specified token.
    */
   public boolean contains(String token);

   /**
    * Returns {@code true} if this ticket contains any of the specified tokens.
    *
    * @param tokens - Set of tokens to check
    * @return {@code true} is this ticket contains any of the specified tokens
    */
   public boolean containsAny(Set<String> tokens);


   /**
    * Returns the application custom user data associated with this ticket.
    *
    * @return the user data associated with this ticket.
    */
   public String getUserData();

   /**
    * Returns the checksum for this ticket which can be used to validate its
    * authenticity. Will return a zero length checksum if the ticket has not
    * been encoded.
    *
    * @return the authentication checksum for this ticket
    */
   public byte[] getChecksum();
   
}
