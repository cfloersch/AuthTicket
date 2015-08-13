package xpertss.auth.tkt;

/**
 * Thrown to indicate that the timestamp associated with the auth ticket
 * has expired.
 */
public class ExpiredTicketException extends TicketNotFoundException {

   public ExpiredTicketException() {
   }

   public ExpiredTicketException(String message) {
      super(message);
   }

   public ExpiredTicketException(String message, Throwable cause) {
      super(message, cause);
   }

   public ExpiredTicketException(Throwable cause) {
      super(cause);
   }
}
