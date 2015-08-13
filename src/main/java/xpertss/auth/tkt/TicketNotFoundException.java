package xpertss.auth.tkt;

/**
 * Thrown to indicate that the auth ticket cookie was not found
 */
public class TicketNotFoundException extends RuntimeException {

   public TicketNotFoundException() {
   }

   public TicketNotFoundException(String message) {
      super(message);
   }

   public TicketNotFoundException(String message, Throwable cause) {
      super(message, cause);
   }

   public TicketNotFoundException(Throwable cause) {
      super(cause);
   }

}
