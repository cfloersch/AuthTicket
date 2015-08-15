/**
 * Copyright 2015 XpertSoftware
 * <p/>
 * Created By: cfloersch
 * Date: 8/15/2015
 */
package xpertss.auth.tkt;

import org.junit.Test;

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;

import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class BasicConfigTest {


   @Test(expected = IllegalArgumentException.class)
   public void testMissingSecret() throws ServletException
   {
      FilterConfig config = mock(FilterConfig.class);
      AuthTicketFilter objectUnderTest = new AuthTicketFilter();
      objectUnderTest.init(config);
   }

   @Test(expected = IllegalArgumentException.class)
   public void testMissingAuthUrl() throws ServletException
   {
      FilterConfig config = mock(FilterConfig.class);
      when(config.getInitParameter(eq("TKTAuthSecret"))).thenReturn("some_random_secret_key");
      AuthTicketFilter objectUnderTest = new AuthTicketFilter();
      objectUnderTest.init(config);
   }

   @Test(expected = IllegalArgumentException.class)
   public void testInvalidAuthUrl() throws ServletException
   {
      FilterConfig config = mock(FilterConfig.class);
      when(config.getInitParameter(eq("TKTAuthSecret"))).thenReturn("some_random_secret_key");
      when(config.getInitParameter(eq("TKTAuthLoginURL"))).thenReturn("hello kitty");
      AuthTicketFilter objectUnderTest = new AuthTicketFilter();
      objectUnderTest.init(config);
   }

   @Test(expected = IllegalArgumentException.class)
   public void testFtpAuthUrl() throws ServletException
   {
      FilterConfig config = mock(FilterConfig.class);
      when(config.getInitParameter(eq("TKTAuthSecret"))).thenReturn("some_random_secret_key");
      when(config.getInitParameter(eq("TKTAuthLoginURL"))).thenReturn("ftp://ftp.manheim.com/");
      AuthTicketFilter objectUnderTest = new AuthTicketFilter();
      objectUnderTest.init(config);
   }

   @Test(expected = IllegalArgumentException.class)
   public void testInvalidDuration() throws ServletException
   {
      FilterConfig config = mock(FilterConfig.class);
      when(config.getInitParameter(eq("TKTAuthSecret"))).thenReturn("some_random_secret_key");
      when(config.getInitParameter(eq("TKTAuthLoginURL"))).thenReturn("https://www.manheim.com/login");
      when(config.getInitParameter(eq("TKTAuthTimeout"))).thenReturn("hello");
      AuthTicketFilter objectUnderTest = new AuthTicketFilter();
      objectUnderTest.init(config);
   }

}
