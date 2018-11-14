package xpertss.auth.tkt;

import org.junit.Test;
import xpertss.threads.NewThreadExecutor;

import java.security.MessageDigest;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.FutureTask;

import static org.junit.Assert.*;

public class DigestAlgorithmTest {

   @Test(expected = MalformedTicketException.class)
   public void testMD5ParseInvalidLengthTicketOne()
   {
      DigestAlgorithm.MD5.parse("aabbccddeeffgg");
   }

   @Test(expected = MalformedTicketException.class)
   public void testMD5ParseInvalidLengthTicketTwo()
   {
      DigestAlgorithm.MD5.parse("00112233445566778899aabbccddeeff");
   }

   @Test(expected = MalformedTicketException.class)
   public void testMD5ParseInvalidLengthTicketThree()
   {
      DigestAlgorithm.MD5.parse("00112233445566778899aabbccddeeffaabbccdd");
   }

   @Test(expected = MalformedTicketException.class)
   public void testMD5ParseMissingExclamationMark()
   {
      DigestAlgorithm.MD5.parse("00112233445566778899aabbccddeeffaabbccddcfloersch");
   }


   @Test
   public void testMD5ParseMinimal()
   {
      AuthTicket ticket = DigestAlgorithm.MD5.parse("00112233445566778899aabbccddeeffaabbccddcfloersch!");
      assertEquals("cfloersch", ticket.getUsername());
      assertEquals(Long.valueOf("aabbccdd", 16).longValue(), ticket.getTimestamp());
      assertEquals("", ticket.getUserData());
      assertTrue(ticket.getTokens().isEmpty());
   }

   @Test
   public void testMD5ParseEmptyTokensAndUserData()
   {
      AuthTicket ticket = DigestAlgorithm.MD5.parse("00112233445566778899aabbccddeeffaabbccddcfloersch!!");
      assertEquals("cfloersch", ticket.getUsername());
      assertEquals(Long.valueOf("aabbccdd", 16).longValue(), ticket.getTimestamp());
      assertEquals("", ticket.getUserData());
      assertTrue(ticket.getTokens().isEmpty());
   }

   @Test
   public void testMD5ParseEmptyUserData()
   {
      AuthTicket ticket = DigestAlgorithm.MD5.parse("00112233445566778899aabbccddeeffaabbccddcfloersch!admin!");
      assertEquals("cfloersch", ticket.getUsername());
      assertEquals(Long.valueOf("aabbccdd", 16).longValue(), ticket.getTimestamp());
      assertEquals("", ticket.getUserData());
      assertEquals(1, ticket.getTokens().size());
      assertTrue(ticket.contains("admin"));
   }

   @Test
   public void testMD5ParseEmptyTokens()
   {
      AuthTicket ticket = DigestAlgorithm.MD5.parse("00112233445566778899aabbccddeeffaabbccddcfloersch!!Chris");
      assertEquals("cfloersch", ticket.getUsername());
      assertEquals(Long.valueOf("aabbccdd", 16).longValue(), ticket.getTimestamp());
      assertEquals("Chris", ticket.getUserData());
      assertTrue(ticket.getTokens().isEmpty());
   }

   @Test
   public void testMD5Parse()
   {
      AuthTicket ticket = DigestAlgorithm.MD5.parse("00112233445566778899aabbccddeeffaabbccddcfloersch!admin,engineer!Chris");
      assertEquals("cfloersch", ticket.getUsername());
      assertEquals(Long.valueOf("aabbccdd", 16).longValue(), ticket.getTimestamp());
      assertEquals("Chris", ticket.getUserData());
      assertEquals(2, ticket.getTokens().size());
      assertTrue(ticket.contains("admin"));
      assertTrue(ticket.contains("engineer"));
      assertFalse(ticket.contains("finance"));
   }

   @Test
   public void testDigestPerThread()
      throws ExecutionException, InterruptedException
   {
      Executor executor = new NewThreadExecutor();
      Callable<MessageDigest> retriever = () -> DigestAlgorithm.MD5.digest();

      FutureTask<MessageDigest> one = new FutureTask<>(retriever);
      executor.execute(one);

      FutureTask<MessageDigest> two = new FutureTask<>(retriever);
      executor.execute(two);

      assertNotSame(one.get(), two.get());
   }

   @Test
   public void testDigests()
   {
      assertEquals("MD5", DigestAlgorithm.MD5.digest().getAlgorithm());
      assertEquals("SHA-256", DigestAlgorithm.SHA256.digest().getAlgorithm());
      assertEquals("SHA-512", DigestAlgorithm.SHA512.digest().getAlgorithm());
   }


}