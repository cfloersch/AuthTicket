package xpertss.auth.tkt;


import xpertss.lang.Objects;

import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

/**
 *
 */
public class AuthTicketConfig {

   private DigestAlgorithm digestAlg = DigestAlgorithm.MD5;
   private Set<String> tokens = Collections.emptySet();
   private String cookieName = "auth_tkt";
   private boolean ignoreIP = false;
   private long timeout = 7200;
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
