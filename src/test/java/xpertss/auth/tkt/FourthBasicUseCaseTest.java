package xpertss.auth.tkt;

import org.junit.Before;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Basic use case configures both the timeout url and the authUrl, allow guests and guest fallback, does
 * not use tokens, and ignores IP addresses.
 *
 * It is intended to test guest functionality as well as the expires functionality.
 */
public class FourthBasicUseCaseTest {

   private AuthTicketFilter objectUnderTest;
   private HttpServletResponse response;
   private HttpServletRequest request;
   private FilterChain chain;
   private Cookie cookie;

   @Before
   public void setUp()
      throws ServletException
   {
      request = mock(HttpServletRequest.class);
      when(request.getRequestURI()).thenReturn("/simulcast/showBuyerSales.do");
      when(request.getQueryString()).thenReturn("filter=AAA");
      when(request.getRemoteAddr()).thenReturn("192.168.1.12");

      response = mock(HttpServletResponse.class);

      FilterConfig config = mock(FilterConfig.class);
      when(config.getInitParameter(eq("TKTAuthSecret"))).thenReturn("some_random_secret_key");
      when(config.getInitParameter(eq("TKTAuthIgnoreIP"))).thenReturn("on");  // Exclude source IP
      when(config.getInitParameter(eq("TKTAuthLoginURL"))).thenReturn("https://www.manheim.com/login");
      when(config.getInitParameter(eq("TKTAuthTimeoutURL"))).thenReturn("https://www.manheim.com/login?timeout=1");
      when(config.getInitParameter(eq("TKTAuthPostTimeoutURL"))).thenReturn("https://www.manheim.com/login?timeout=2");
      when(config.getInitParameter(eq("TKTAuthGuestLogin"))).thenReturn("on");  // Support Guest access
      when(config.getInitParameter(eq("TKTAuthGuestFallback"))).thenReturn("on");  // Support Guest fallback


      objectUnderTest = new AuthTicketFilter();
      objectUnderTest.init(config);

      cookie = mock(Cookie.class);
      chain = mock(FilterChain.class);
   }


   @Test
   public void testNoCookie() throws ServletException, IOException
   {
      when(request.getCookies()).thenReturn(new Cookie[0]);
      when(request.getScheme()).thenReturn("https");
      when(request.getHeader(eq("Host"))).thenReturn("simulcast.manheim.com");

      doAnswer(new Answer() {
         @Override
         public Object answer(InvocationOnMock invocation)
            throws Throwable
         {
            HttpServletRequest httpRequest = (HttpServletRequest) invocation.getArguments()[0];
            assertFalse(httpRequest.isUserInRole("Workbook+OVE"));
            assertFalse(httpRequest.isUserInRole("Simulcast"));
            assertEquals("guest", httpRequest.getRemoteUser());
            assertEquals("AUTH_TKT", httpRequest.getAuthType());
            assertNull(httpRequest.getAttribute("TKTAuthUserData"));
            return null;
         }
      }).when(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

      objectUnderTest.doFilter(request, response, chain);

      verify(chain, times(1)).doFilter(any(ServletRequest.class), any(ServletResponse.class));
   }

   @Test
   public void testMisNamedCookie() throws ServletException, IOException
   {
      when(cookie.getName()).thenReturn("MisNamed");

      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      when(request.getScheme()).thenReturn("https");
      when(request.getHeader(eq("Host"))).thenReturn("simulcast.manheim.com");


      doAnswer(new Answer() {
         @Override
         public Object answer(InvocationOnMock invocation)
            throws Throwable
         {
            HttpServletRequest httpRequest = (HttpServletRequest) invocation.getArguments()[0];
            assertFalse(httpRequest.isUserInRole("Workbook+OVE"));
            assertFalse(httpRequest.isUserInRole("Simulcast"));
            assertEquals("guest", httpRequest.getRemoteUser());
            assertEquals("AUTH_TKT", httpRequest.getAuthType());
            assertNull(httpRequest.getAttribute("TKTAuthUserData"));
            return null;
         }
      }).when(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

      objectUnderTest.doFilter(request, response, chain);

      verify(chain, times(1)).doFilter(any(ServletRequest.class), any(ServletResponse.class));
   }

   @Test
   public void testEmptyCookie() throws ServletException, IOException
   {
      when(cookie.getName()).thenReturn("auth_tkt");
      when(cookie.getValue()).thenReturn("");

      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      when(request.getScheme()).thenReturn("https");
      when(request.getHeader(eq("Host"))).thenReturn("simulcast.manheim.com");


      doAnswer(new Answer() {
         @Override
         public Object answer(InvocationOnMock invocation)
            throws Throwable
         {
            HttpServletRequest httpRequest = (HttpServletRequest) invocation.getArguments()[0];
            assertFalse(httpRequest.isUserInRole("Workbook+OVE"));
            assertFalse(httpRequest.isUserInRole("Simulcast"));
            assertEquals("guest", httpRequest.getRemoteUser());
            assertEquals("AUTH_TKT", httpRequest.getAuthType());
            assertNull(httpRequest.getAttribute("TKTAuthUserData"));
            return null;
         }
      }).when(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

      objectUnderTest.doFilter(request, response, chain);

      verify(chain, times(1)).doFilter(any(ServletRequest.class), any(ServletResponse.class));
   }

   @Test
   public void testMalformedCookie() throws ServletException, IOException
   {
      when(cookie.getName()).thenReturn("auth_tkt");
      when(cookie.getValue()).thenReturn("00112233445566778899aabbccddeeff00000000cfloersch");

      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      when(request.getScheme()).thenReturn("https");
      when(request.getHeader(eq("Host"))).thenReturn("simulcast.manheim.com");


      doAnswer(new Answer() {
         @Override
         public Object answer(InvocationOnMock invocation)
            throws Throwable
         {
            HttpServletRequest httpRequest = (HttpServletRequest) invocation.getArguments()[0];
            assertFalse(httpRequest.isUserInRole("Workbook+OVE"));
            assertFalse(httpRequest.isUserInRole("Simulcast"));
            assertEquals("guest", httpRequest.getRemoteUser());
            assertEquals("AUTH_TKT", httpRequest.getAuthType());
            assertNull(httpRequest.getAttribute("TKTAuthUserData"));
            return null;
         }
      }).when(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

      objectUnderTest.doFilter(request, response, chain);

      verify(chain, times(1)).doFilter(any(ServletRequest.class), any(ServletResponse.class));
   }


   @Test
   public void testInvalidCookie() throws ServletException, IOException
   {
      when(cookie.getName()).thenReturn("auth_tkt");
      when(cookie.getValue()).thenReturn("00112233445566778899aabbccddeeffffffffffcfloersch!Chris");

      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      when(request.getScheme()).thenReturn("https");
      when(request.getHeader(eq("Host"))).thenReturn("simulcast.manheim.com");


      doAnswer(new Answer() {
         @Override
         public Object answer(InvocationOnMock invocation)
            throws Throwable
         {
            HttpServletRequest httpRequest = (HttpServletRequest) invocation.getArguments()[0];
            assertFalse(httpRequest.isUserInRole("Workbook+OVE"));
            assertFalse(httpRequest.isUserInRole("Simulcast"));
            assertEquals("guest", httpRequest.getRemoteUser());
            assertEquals("AUTH_TKT", httpRequest.getAuthType());
            assertNull(httpRequest.getAttribute("TKTAuthUserData"));
            return null;
         }
      }).when(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

      objectUnderTest.doFilter(request, response, chain);

      verify(chain, times(1)).doFilter(any(ServletRequest.class), any(ServletResponse.class));
   }



   @Test
   public void testModifiedCase() throws ServletException, IOException
   {
      when(cookie.getName()).thenReturn("auth_tkt");
      when(cookie.getValue()).thenReturn("e400af8d8448df14b22193dfdcebe22bffff64a9cfloersch%21Workbook%2BOVE%21Chris%2BFloersch");
      // Modified the timestamp so it wouldn't show as expired.. But in doing so it made the ticket invalid

      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      when(request.getScheme()).thenReturn("https");
      when(request.getHeader(eq("Host"))).thenReturn("simulcast.manheim.com");
      when(request.getMethod()).thenReturn("GET");

      doAnswer(new Answer() {
         @Override
         public Object answer(InvocationOnMock invocation)
            throws Throwable
         {
            HttpServletRequest httpRequest = (HttpServletRequest) invocation.getArguments()[0];
            assertFalse(httpRequest.isUserInRole("Workbook+OVE"));
            assertFalse(httpRequest.isUserInRole("Simulcast"));
            assertEquals("guest", httpRequest.getRemoteUser());
            assertEquals("AUTH_TKT", httpRequest.getAuthType());
            assertNull(httpRequest.getAttribute("TKTAuthUserData"));
            return null;
         }
      }).when(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

      objectUnderTest.doFilter(request, response, chain);

      verify(chain, times(1)).doFilter(any(ServletRequest.class), any(ServletResponse.class));

   }


   @Test
   public void testTimedoutGetCase() throws ServletException, IOException
   {
      when(cookie.getName()).thenReturn("auth_tkt");
      when(cookie.getValue()).thenReturn("e400af8d8448df14b22193dfdcebe22b55ce64a9cfloersch%21Workbook%2BOVE%21Chris%2BFloersch");

      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      when(request.getScheme()).thenReturn("https");
      when(request.getHeader(eq("Host"))).thenReturn("simulcast.manheim.com");
      when(request.getMethod()).thenReturn("GET");

      doAnswer(new Answer() {
         @Override
         public Object answer(InvocationOnMock invocation)
            throws Throwable
         {
            HttpServletRequest httpRequest = (HttpServletRequest) invocation.getArguments()[0];
            assertFalse(httpRequest.isUserInRole("Workbook+OVE"));
            assertFalse(httpRequest.isUserInRole("Simulcast"));
            assertEquals("guest", httpRequest.getRemoteUser());
            assertEquals("AUTH_TKT", httpRequest.getAuthType());
            assertNull(httpRequest.getAttribute("TKTAuthUserData"));
            return null;
         }
      }).when(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

      objectUnderTest.doFilter(request, response, chain);

      verify(chain, times(1)).doFilter(any(ServletRequest.class), any(ServletResponse.class));

   }

   @Test
   public void testTimedoutPostCase() throws ServletException, IOException
   {
      when(cookie.getName()).thenReturn("auth_tkt");
      when(cookie.getValue()).thenReturn("e400af8d8448df14b22193dfdcebe22b55ce64a9cfloersch%21Workbook%2BOVE%21Chris%2BFloersch");

      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      when(request.getScheme()).thenReturn("https");
      when(request.getHeader(eq("Host"))).thenReturn("simulcast.manheim.com");
      when(request.getMethod()).thenReturn("POST");

      doAnswer(new Answer() {
         @Override
         public Object answer(InvocationOnMock invocation)
            throws Throwable
         {
            HttpServletRequest httpRequest = (HttpServletRequest) invocation.getArguments()[0];
            assertFalse(httpRequest.isUserInRole("Workbook+OVE"));
            assertFalse(httpRequest.isUserInRole("Simulcast"));
            assertEquals("guest", httpRequest.getRemoteUser());
            assertEquals("AUTH_TKT", httpRequest.getAuthType());
            assertNull(httpRequest.getAttribute("TKTAuthUserData"));
            return null;
         }
      }).when(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

      objectUnderTest.doFilter(request, response, chain);

      verify(chain, times(1)).doFilter(any(ServletRequest.class), any(ServletResponse.class));

   }


}