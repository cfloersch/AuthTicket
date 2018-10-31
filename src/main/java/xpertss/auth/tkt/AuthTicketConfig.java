package xpertss.auth.tkt;


import xpertss.lang.Numbers;
import xpertss.lang.Objects;
import xpertss.lang.Strings;
import xpertss.util.Sets;

import java.util.Set;

/**
 * Configuration object for parsing and encoding {@link xpertss.auth.tkt.AuthTicket}s
 */
public class AuthTicketConfig {

   private DigestAlgorithm digestAlg = DigestAlgorithm.MD5;
   private Set<String> tokens = Sets.newHashSet();
   private String cookieName = "auth_tkt";
   private boolean ignoreIP = true;
   private long timeout = 7200;
   private String secret;


   /**
    * Create an AuthTicketConfig instance using the specified secret key
    *
    * @param secret - the secret key used to encode and validate the ticket
    */
   public AuthTicketConfig(String secret)
   {
      this.secret = Strings.notEmpty(secret, "secret");
   }

   /**
    * Returns the secret key used to encode and validate tickets.
    *
    * @return the secret key used to encode and validate tickets.
    */
   public String getSecret()
   {
      return secret;
   }


   /**
    * Get teh configured digest algorithm. By default ModAuthTicket uses MD5
    * which is generally considered to be compromised.
    *
    * @return the configured digest algorithm to use in encoding and validation
    */
   public DigestAlgorithm getDigestAlgorithm()
   {
      return digestAlg;
   }

   /**
    * Sets the digest algorithm used to encode and validate auth tickets.
    *
    * @param digestAlg the digest algorithm to use to encode and validate tickets.
    */
   public void setDigestAlgorithm(DigestAlgorithm digestAlg)
   {
      this.digestAlg = Objects.notNull(digestAlg, "digestAlg");
   }


   /**
    * Returns the name of the cookie. It defaults to "auth_tkt" if not explicitly
    * specified.
    *
    * @return the name of the auth ticket cookie.
    */
   public String getCookieName()
   {
      return cookieName;
   }

   /**
    * Set the name of the cookie used to transfer auth ticket credentials.
    *
    * @param cookieName the name of the cookie that holds the auth ticket
    */
   public void setCookieName(String cookieName)
   {
      this.cookieName = Strings.notEmpty(cookieName, "cookieName");
   }


   /**
    * Returns {@code true} if IP verification has been disabled, {@code false}
    * otherwise.
    *
    * @return whether the client's IP should be verified
    */
   public boolean ignoreIP()
   {
      return ignoreIP;
   }

   /**
    * Enable or disable client IP verification. The default behavior is to ignore the
    * client IP address.
    * <p>
    * Enabling this should be carefully considered as verifying the client IP in a world
    * full of proxies and load balancers can be a tricky and or insecure process.
    *
    * @param checkIp - boolean indicating whether IP verification should be disabled.
    */
   public void setIgnoreIP(boolean checkIp)
   {
      this.ignoreIP = checkIp;
   }


   /**
    * A configurable timeout period measured in seconds.
    *
    * @return the timeout period after which tickets will be ignored
    */
   public long getTimeout()
   {
      return timeout;
   }

   /**
    * Number of seconds to timeout the token. This defaults to 7200 seconds or
    * 2 hours.
    */
   public void setTimeout(long timeout) {
      this.timeout = Numbers.gte(0L, timeout, "timeout must be positive");
   }


   /**
    * Returns the set of tokens (aka Roles) that are required to be present in the
    * encoded ticket to be considered valid. The returned set is mutable.
    *
    * @return the required set of tokens
    */
   public Set<String> getTokens()
   {
      return tokens;
   }

   /**
    * Set the required set of tokens that must be present in the encoded ticket
    * to be considered valid.
    * <p>
    * An empty set is a valid option, but {@code null} sets are not accepted.
    *
    * @param tokens the required set of tokens
    */
   public void setTokens(Set<String> tokens)
   {
      this.tokens = Objects.notNull(tokens, "tokens");
   }


   @Override
   public boolean equals(Object o)
   {
      if(o instanceof AuthTicketConfig) {
         AuthTicketConfig other = (AuthTicketConfig) o;
         return ignoreIP == other.ignoreIP &&
                  timeout == other.timeout &&
                  digestAlg == other.digestAlg &&
                  Objects.equal(tokens, other.tokens) &&
                  Objects.equal(cookieName, other.cookieName) &&
                  Objects.equal(secret, other.secret);

      }
      return false;
   }

   @Override
   public int hashCode()
   {
      return Objects.hash(digestAlg, tokens, cookieName, ignoreIP, timeout, secret);
   }
   
}
