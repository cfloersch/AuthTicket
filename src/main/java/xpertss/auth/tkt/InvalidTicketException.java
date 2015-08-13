package xpertss.auth.tkt;

/**
 * Thrown to indicate that the ticket did not authenticate properly.
 */
public class InvalidTicketException extends RuntimeException {
   public InvalidTicketException() {
   }

   public InvalidTicketException(String message) {
      super(message);
   }

   public InvalidTicketException(String message, Throwable cause) {
      super(message, cause);
   }

   public InvalidTicketException(Throwable cause) {
      super(cause);
   }
}
