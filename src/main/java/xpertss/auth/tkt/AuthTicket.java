/*
 * Copyright 2018 XpertSoftware
 *
 * Created By: cfloersch
 * Date: 10/25/2018
 */
package xpertss.auth.tkt;

import java.util.Set;

/**
 * A basic interface for AuthTicket data and functionality.
 * <p>
 * From the specification
 * <p><pre>
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
 * </pre>
 */
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
    * <p>
    * Will return {@code true} if the supplied token set is empty.
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

   /**
    * Returns the ticket's data as a HTTP safe encoded string. Generally speaking
    * this simply URL Encodes the data returned from {@link Object#toString()}.
    *
    * @return an HTTP header safe encoding of the ticket
    */
   public String getEncoded();
}
