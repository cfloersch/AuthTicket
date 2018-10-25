package xpertss.auth.tkt;

import org.junit.Test;
import xpertss.threads.NewThreadExecutor;

import java.security.MessageDigest;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.FutureTask;

import static org.junit.Assert.*;

/**
 * Copyright 2015 XpertSoftware
 * <p/>
 * Created By: cfloersch
 * Date: 8/14/2015
 */
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
      EncodedAuthTicket ticket = DigestAlgorithm.MD5.parse("00112233445566778899aabbccddeeffaabbccddcfloersch!");
      assertEquals("cfloersch", ticket.getUsername());
      assertEquals(Long.valueOf("aabbccdd", 16).longValue(), ticket.getTimestamp());
      assertEquals("", ticket.getUserData());
      assertNull(ticket.getTokens());
   }

   @Test
   public void testMD5ParseEmptyTokensAndUserData()
   {
      EncodedAuthTicket ticket = DigestAlgorithm.MD5.parse("00112233445566778899aabbccddeeffaabbccddcfloersch!!");
      assertEquals("cfloersch", ticket.getUsername());
      assertEquals(Long.valueOf("aabbccdd", 16).longValue(), ticket.getTimestamp());
      assertEquals("", ticket.getUserData());
      assertEquals("", ticket.getTokens());
   }

   @Test
   public void testMD5ParseEmptyUserData()
   {
      EncodedAuthTicket ticket = DigestAlgorithm.MD5.parse("00112233445566778899aabbccddeeffaabbccddcfloersch!admin!");
      assertEquals("cfloersch", ticket.getUsername());
      assertEquals(Long.valueOf("aabbccdd", 16).longValue(), ticket.getTimestamp());
      assertEquals("", ticket.getUserData());
      assertEquals("admin", ticket.getTokens());
   }

   @Test
   public void testMD5ParseEmptyTokens()
   {
      EncodedAuthTicket ticket = DigestAlgorithm.MD5.parse("00112233445566778899aabbccddeeffaabbccddcfloersch!!Chris");
      assertEquals("cfloersch", ticket.getUsername());
      assertEquals(Long.valueOf("aabbccdd", 16).longValue(), ticket.getTimestamp());
      assertEquals("Chris", ticket.getUserData());
      assertEquals("", ticket.getTokens());
   }

   @Test
   public void testMD5Parse()
   {
      EncodedAuthTicket ticket = DigestAlgorithm.MD5.parse("00112233445566778899aabbccddeeffaabbccddcfloersch!admin,engineer!Chris");
      assertEquals("cfloersch", ticket.getUsername());
      assertEquals(Long.valueOf("aabbccdd", 16).longValue(), ticket.getTimestamp());
      assertEquals("Chris", ticket.getUserData());
      assertEquals("admin,engineer", ticket.getTokens());
      assertTrue(ticket.contains("admin"));
      assertTrue(ticket.contains("engineer"));
      assertFalse(ticket.contains("finance"));
   }

   @Test
   public void testDigestPerThread()
      throws ExecutionException, InterruptedException
   {
      Executor executor = new NewThreadExecutor();
      Callable<MessageDigest> retriever = new Callable<MessageDigest>() {
         @Override
         public MessageDigest call() throws Exception
         {
            return DigestAlgorithm.MD5.digest();
         }
      };

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