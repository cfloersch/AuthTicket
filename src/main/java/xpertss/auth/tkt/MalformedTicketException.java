package xpertss.auth.tkt;

/**
 * Thrown to indicate the auth ticket is not of the correct form and
 * should be treated in a similar way as if the ticket was not found.
 */
public class MalformedTicketException extends TicketNotFoundException {
   public MalformedTicketException() {
   }

   public MalformedTicketException(String message) {
      super(message);
   }

   public MalformedTicketException(String message, Throwable cause) {
      super(message, cause);
   }

   public MalformedTicketException(Throwable cause) {
      super(cause);
   }
}
