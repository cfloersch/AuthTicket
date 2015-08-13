package xpertss.auth.tkt;

/**
 * Thrown to indicate that this valid ticket does not contain the required
 * token. This exception should treated as an authorization failure.
 */
public class TokenMissingException extends InvalidTicketException {
   public TokenMissingException() {
   }

   public TokenMissingException(String message) {
      super(message);
   }

   public TokenMissingException(String message, Throwable cause) {
      super(message, cause);
   }

   public TokenMissingException(Throwable cause) {
      super(cause);
   }
}
