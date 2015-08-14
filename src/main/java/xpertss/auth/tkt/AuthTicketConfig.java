package xpertss.auth.tkt;


import xpertss.lang.Objects;

import java.util.Set;

/**
 *
 */
public class AuthTicketConfig {

   private String cookieName = "auth_tkt";
   private boolean ignoreIP = false;
   private long timeout = 3600 * 2;
   private DigestAlgorithm digestAlg;
   private Set<String> tokens;
   private String secret;


   public AuthTicketConfig(String secret)
   {
      this.secret = Objects.notNull(secret, "secret");
   }

   public String getSecret() {
      return secret;
   }



   public DigestAlgorithm getDigestAlgorithm()
   {
      return digestAlg;
   }

   public void setDigestAlgorithm(DigestAlgorithm digestAlg)
   {
      this.digestAlg = digestAlg;
   }



   public String getCookieName() {
      return cookieName;
   }

   public void setCookieName(String cookieName) {
      this.cookieName = cookieName;
   }




   public boolean ignoreIP() {
      return ignoreIP;
   }

   public void setIgnoreIP(boolean checkIp) {
      this.ignoreIP = checkIp;
   }




   public long getTimeout() {
      return timeout;
   }

   /**
    * Number of seconds to timeout the token
    */
   public void setTimeout(long timeout) {
      this.timeout = timeout;
   }



   public Set<String> getTokens() {
      return tokens;
   }

   public void setTokens(Set<String> tokens) {
      this.tokens = tokens;
   }

}
