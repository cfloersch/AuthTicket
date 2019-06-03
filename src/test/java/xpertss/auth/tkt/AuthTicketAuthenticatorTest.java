package xpertss.auth.tkt;

import org.junit.Before;
import org.junit.Test;
import xpertss.net.NetUtils;
import xpertss.util.Sets;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import java.util.Base64;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


public class AuthTicketAuthenticatorTest {


   private AuthTicketAuthenticator objectUnderTest;
   private HttpServletRequest request;
   private Cookie cookie;

   @Before
   public void setUp()
   {
      cookie = mock(Cookie.class);
      request = mock(HttpServletRequest.class);

   }

   @Test(expected = TicketNotFoundException.class)
   public void testNoCookies()
   {
      when(request.getCookies()).thenReturn(new Cookie[0]);
      objectUnderTest = new AuthTicketAuthenticator("some_random_secret_key");
      objectUnderTest.authenticate(request);
   }

   @Test(expected = TicketNotFoundException.class)
   public void testNoCookie()
   {
      when(cookie.getName()).thenReturn("OtherName");
      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      objectUnderTest = new AuthTicketAuthenticator("some_random_secret_key");
      objectUnderTest.authenticate(request);
   }

   @Test(expected = ExpiredTicketException.class)
   public void testSimpleExpiredTicket()
   {
      when(cookie.getName()).thenReturn("auth_tkt");
      when(cookie.getValue()).thenReturn("00112233445566778899aabbccddeeff00000220cfloersch!data");
      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      objectUnderTest = new AuthTicketAuthenticator("some_random_secret_key");
      objectUnderTest.authenticate(request);
   }

   @Test(expected = ExpiredTicketException.class)
   public void testUrlEncodedExpiredTicket()
   {
      when(cookie.getName()).thenReturn("auth_tkt");
      when(cookie.getValue()).thenReturn(NetUtils.urlEncode("00112233445566778899aabbccddeeff00000220cfloersch!data"));
      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      objectUnderTest = new AuthTicketAuthenticator("some_random_secret_key");
      objectUnderTest.authenticate(request);
   }

   @Test(expected = ExpiredTicketException.class)
   public void testBase64EncodedExpiredTicket()
   {
      when(cookie.getName()).thenReturn("auth_tkt");
      when(cookie.getValue()).thenReturn(Base64.getEncoder().encodeToString("00112233445566778899aabbccddeeff00000220cfloersch!data".getBytes()));
      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      objectUnderTest = new AuthTicketAuthenticator("some_random_secret_key");
      objectUnderTest.authenticate(request);
   }

   @Test(expected = InvalidTicketException.class)
   public void testSimpleInvalidTicket()
   {
      AuthTicketConfig config = new AuthTicketConfig("some_random_secret_key");
      config.setTimeout(0);
      config.setIgnoreIP(true);

      when(cookie.getName()).thenReturn("auth_tkt");
      when(cookie.getValue()).thenReturn("00112233445566778899aabbccddeeff00000220cfloersch!data");
      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      objectUnderTest = new AuthTicketAuthenticator(config);
      objectUnderTest.authenticate(request);
   }

   @Test // vector test
   public void testSimpleValidTicketOne()
   {
      AuthTicketConfig config = new AuthTicketConfig("some_random_secret_key");
      config.setTimeout(0);
      config.setIgnoreIP(true);

      when(cookie.getName()).thenReturn("auth_tkt");
      when(cookie.getValue()).thenReturn("df612274bbd2b88a510b8d9fe9796af655ce6444cfloersch%21Workbook%2BOVE%21Chris%2BFloersch");
      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      objectUnderTest = new AuthTicketAuthenticator(config);
      AuthTicket ticket = objectUnderTest.authenticate(request);
      assertEquals("cfloersch", ticket.getUsername());
      assertEquals("Chris+Floersch", ticket.getUserData());
      assertTrue(ticket.contains("Workbook+OVE"));
   }

   @Test // vector test
   public void testSimpleValidTicketTwo()
   {
      AuthTicketConfig config = new AuthTicketConfig("some_random_secret_key");
      config.setTimeout(0);
      config.setIgnoreIP(true);

      when(cookie.getName()).thenReturn("auth_tkt");
      when(cookie.getValue()).thenReturn("e400af8d8448df14b22193dfdcebe22b55ce64a9cfloersch%21Workbook%2BOVE%21Chris%2BFloersch");
      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      objectUnderTest = new AuthTicketAuthenticator(config);
      AuthTicket ticket = objectUnderTest.authenticate(request);
      assertEquals("cfloersch", ticket.getUsername());
      assertEquals("Chris+Floersch", ticket.getUserData());
      assertTrue(ticket.contains("Workbook+OVE"));
   }




   @Test
   public void testSimpleValidTicketWithTokenAssertion()
   {
      AuthTicketConfig config = new AuthTicketConfig("some_random_secret_key");
      config.setTimeout(0);
      config.setIgnoreIP(true);
      config.setTokens(Sets.of("Workbook+OVE"));

      when(cookie.getName()).thenReturn("auth_tkt");
      when(cookie.getValue()).thenReturn("e400af8d8448df14b22193dfdcebe22b55ce64a9cfloersch%21Workbook%2BOVE%21Chris%2BFloersch");
      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      objectUnderTest = new AuthTicketAuthenticator(config);
      AuthTicket ticket = objectUnderTest.authenticate(request);
      assertEquals("cfloersch", ticket.getUsername());
      assertEquals("Chris+Floersch", ticket.getUserData());
      assertTrue(ticket.contains("Workbook+OVE"));
   }

   @Test(expected = TokenMissingException.class)
   public void testSimpleInvalidTicketWithTokenAssertion()
   {
      AuthTicketConfig config = new AuthTicketConfig("some_random_secret_key");
      config.setTimeout(0);
      config.setIgnoreIP(true);
      config.setTokens(Sets.of("Simulcast"));

      when(cookie.getName()).thenReturn("auth_tkt");
      when(cookie.getValue()).thenReturn("e400af8d8448df14b22193dfdcebe22b55ce64a9cfloersch%21Workbook%2BOVE%21Chris%2BFloersch");
      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      objectUnderTest = new AuthTicketAuthenticator(config);
      objectUnderTest.authenticate(request);
   }

   @Test(expected = InvalidTicketException.class)
   public void testSimpleInvalidTicketWithRemoteIP()
   {
      AuthTicketConfig config = new AuthTicketConfig("some_random_secret_key");
      config.setIgnoreIP(false);
      config.setTimeout(0);

      when(cookie.getName()).thenReturn("auth_tkt");
      when(cookie.getValue()).thenReturn("e400af8d8448df14b22193dfdcebe22b55ce64a9cfloersch%21Workbook%2BOVE%21Chris%2BFloersch");
      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      when(request.getRemoteAddr()).thenReturn("192.168.1.12");
      objectUnderTest = new AuthTicketAuthenticator(config);
      objectUnderTest.authenticate(request);
   }


   @Test
   public void testBase64EncodedMultiToken()
   {
      AuthTicketConfig config = new AuthTicketConfig("some_random_secret_key");
      config.setTimeout(0);
      config.setIgnoreIP(true);

      when(cookie.getName()).thenReturn("auth_tkt");
      when(cookie.getValue()).thenReturn("ZDJmOWFiNjA1OTAyNjU1NmExYWY0OWRiZmFjMjQzOWI1Y2NhMDhmZmNvcnRpbiFhbHBoYXVzZXIsVmVoaWNsZStWYWx1YXRpb24rVG9vbCFDaHJpc3RvcGhlcitBeWQ=");
      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      objectUnderTest = new AuthTicketAuthenticator(config);
      AuthTicket ticket = objectUnderTest.authenticate(request);
      assertEquals("cortin", ticket.getUsername());
      assertEquals("Christopher+Ayd", ticket.getUserData());
      assertTrue(ticket.contains("alphauser"));
      assertTrue(ticket.contains("Vehicle+Valuation+Tool"));
   }

   @Test
   public void testUrlEncodedMultiToken()
   {
      AuthTicketConfig config = new AuthTicketConfig("some_random_secret_key");
      config.setTimeout(0);
      config.setIgnoreIP(true);

      when(cookie.getName()).thenReturn("auth_tkt");
      when(cookie.getValue()).thenReturn("0657e2f28abd6ef7bb63b0a5c84b834d5cc9f7f8cortin%21alphauser%2CVehicle%2BValuation%2BTool%21Christopher%2BAyd");
      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      objectUnderTest = new AuthTicketAuthenticator(config);
      AuthTicket ticket = objectUnderTest.authenticate(request);
      assertEquals("cortin", ticket.getUsername());
      assertEquals("Christopher+Ayd", ticket.getUserData());
      assertTrue(ticket.contains("alphauser"));
      assertTrue(ticket.contains("Vehicle+Valuation+Tool"));
   }



}