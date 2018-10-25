package xpertss.auth.tkt;

import org.junit.Test;
import xpertss.util.Sets;

import static org.junit.Assert.*;

/**
 * Copyright 2015 XpertSoftware
 * <p/>
 * Created By: cfloersch
 * Date: 8/14/2015
 */
public class AuthTicketTest {

   private static final byte[] checksum = { (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03 };

   @Test
   public void testContainsNullTokenSet()
   {
      EncodedAuthTicket ticket = EncodedAuthTicket.create(checksum, 100, "cfloersch", null, "Chris");
      assertFalse(ticket.contains("admin"));
   }

   @Test
   public void testContainsEmptyTokenSet()
   {
      EncodedAuthTicket ticket = EncodedAuthTicket.create(checksum, 100, "cfloersch", "", "Chris");
      assertFalse(ticket.contains("admin"));
   }

   @Test
   public void testContainsSingleEntryTokenSet()
   {
      EncodedAuthTicket ticket = EncodedAuthTicket.create(checksum, 100, "cfloersch", "finance", "Chris");
      assertFalse(ticket.contains("admin"));
      assertTrue(ticket.contains("finance"));
   }

   @Test
   public void testContainsMultiEntryTokenSet()
   {
      EncodedAuthTicket ticket = EncodedAuthTicket.create(checksum, 100, "cfloersch", "finance,admin,config", "Chris");
      assertTrue(ticket.contains("admin"));
      assertTrue(ticket.contains("finance"));
      assertTrue(ticket.contains("config"));
      assertFalse(ticket.contains("super"));
   }

   @Test
   public void testIsExpired()
   {
      long current = (System.currentTimeMillis() / 1000) - 100;
      EncodedAuthTicket ticket = EncodedAuthTicket.create(checksum, current, "cfloersch", null, "Chris");
      assertFalse(ticket.isExpired(0));
      assertTrue(ticket.isExpired(10));
      assertTrue(ticket.isExpired(99));
      assertTrue(ticket.isExpired(100));
      assertFalse(ticket.isExpired(101));
   }

   @Test
   public void testContainsAnyMultiEntryTokenSet()
   {
      EncodedAuthTicket ticket = EncodedAuthTicket.create(checksum, 100, "cfloersch", "finance,admin,config", "Chris");
      assertTrue(ticket.containsAny(Sets.of("admin", "finance")));
      assertTrue(ticket.containsAny(Sets.of("admin")));
      assertTrue(ticket.containsAny(Sets.of("finance")));
      assertFalse(ticket.containsAny(Sets.of("marketing", "sale")));
   }

   @Test
   public void testContainsAnyNullTokenSet()
   {
      EncodedAuthTicket ticket = EncodedAuthTicket.create(checksum, 100, "cfloersch", null, "Chris");
      assertFalse(ticket.containsAny(Sets.of("admin", "finance")));
      assertFalse(ticket.containsAny(Sets.of("admin")));
      assertFalse(ticket.containsAny(Sets.of("finance")));
      assertFalse(ticket.containsAny(Sets.of("marketing", "sale")));
   }

   @Test
   public void testContainsAnyEmptyTokenSet()
   {
      EncodedAuthTicket ticket = EncodedAuthTicket.create(checksum, 100, "cfloersch", "", "Chris");
      assertFalse(ticket.containsAny(Sets.of("admin", "finance")));
      assertFalse(ticket.containsAny(Sets.of("admin")));
      assertFalse(ticket.containsAny(Sets.of("finance")));
      assertFalse(ticket.containsAny(Sets.of("marketing", "sale")));
   }

   @Test(expected = NullPointerException.class)
   public void testCreateNullChecksum()
   {
      EncodedAuthTicket.create(null, 100, "cfloersch", "", "Chris");
   }

   @Test(expected = IllegalArgumentException.class)
   public void testCreateEmptyChecksum()
   {
      EncodedAuthTicket.create(new byte[0], 100, "cfloersch", "", "Chris");
   }

   @Test(expected = NullPointerException.class)
   public void testCreateNullUserData()
   {
      EncodedAuthTicket.create(checksum, 100, "cfloersch", "", null);
   }

   @Test(expected = IllegalArgumentException.class)
   public void testCreateNullUid()
   {
      EncodedAuthTicket.create(checksum, 100, null, "", "Chris");
   }

   @Test(expected = IllegalArgumentException.class)
   public void testCreateEmptyUid()
   {
      EncodedAuthTicket.create(checksum, 100, "", "", "Chris");
   }

}