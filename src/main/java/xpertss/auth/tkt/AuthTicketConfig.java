package xpertss.auth.tkt;


import java.util.Objects;

/**
 *
 */
public class AuthTicketConfig {

   private String cookieName = "auth_tkt";
   private boolean ignoreIP = true;
   private long timeout = 0;
   private String secret;
   private String token;


   public AuthTicketConfig(String secret)
   {
      this.secret = Objects.requireNonNull(secret);
   }

   public String getSecret() {
      return secret;
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




   public String getToken() {
      return token;
   }

   public void setToken(String token) {
      this.token = token;
   }

}
