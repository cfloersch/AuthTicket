package xpertss.auth.tkt;

import org.junit.Before;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import xpertss.net.NetUtils;

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
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Basic use case configures only the single authUrl, does not allow guests, does require
 * tokens, and ignores IP addresses.
 */
public class FifthBasicUseCaseTest {

   private AuthTicketFilter objectUnderTestAll;
   private AuthTicketFilter objectUnderTestSimulcast;
   private AuthTicketFilter objectUnderTestWorkbook;


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
      when(config.getInitParameter(eq("TKTAuthTimeout"))).thenReturn("0");    // No timeout
      when(config.getInitParameter(eq("TKTAuthLoginURL"))).thenReturn("https://www.manheim.com/login?type=auth");
      when(config.getInitParameter(eq("TKTAuthUnauthURL"))).thenReturn("https://www.manheim.com/login?type=role");

      when(config.getInitParameter(eq("TKTAuthToken"))).thenReturn("Workbook+OVE,Simulcast");
      objectUnderTestAll = new AuthTicketFilter();
      objectUnderTestAll.init(config);

      when(config.getInitParameter(eq("TKTAuthToken"))).thenReturn("Workbook+OVE");
      objectUnderTestWorkbook = new AuthTicketFilter();
      objectUnderTestWorkbook.init(config);

      when(config.getInitParameter(eq("TKTAuthToken"))).thenReturn("Simulcast");
      objectUnderTestSimulcast = new AuthTicketFilter();
      objectUnderTestSimulcast.init(config);

      cookie = mock(Cookie.class);
      chain = mock(FilterChain.class);
   }





   @Test
   public void testInvalidCookie() throws ServletException, IOException
   {
      when(cookie.getName()).thenReturn("auth_tkt");
      when(cookie.getValue()).thenReturn("00112233445566778899aabbccddeeff00000000cfloersch!Chris");

      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      when(request.getScheme()).thenReturn("https");
      when(request.getHeader(eq("Host"))).thenReturn("simulcast.manheim.com");


      objectUnderTestAll.doFilter(request, response, chain);

      verify(response, times(1)).setHeader(eq("Location"), eq("https://www.manheim.com/login?type=auth&back=" +
            NetUtils.urlEncode("https://simulcast.manheim.com/simulcast/showBuyerSales.do?filter=AAA")));
      verify(response, times(1)).setStatus(eq(HttpServletResponse.SC_FOUND));
      verify(chain, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));
   }




   @Test
   public void testValidWorkbookCase() throws ServletException, IOException
   {
      when(cookie.getName()).thenReturn("auth_tkt");
      when(cookie.getValue()).thenReturn("e400af8d8448df14b22193dfdcebe22b55ce64a9cfloersch%21Workbook%2BOVE%21Chris%2BFloersch");

      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      when(request.getScheme()).thenReturn("https");
      when(request.getHeader(eq("Host"))).thenReturn("simulcast.manheim.com");

      doAnswer(new Answer() {
         @Override
         public Object answer(InvocationOnMock invocation)
            throws Throwable
         {
            HttpServletRequest httpRequest = (HttpServletRequest) invocation.getArguments()[0];
            assertTrue(httpRequest.isUserInRole("Workbook+OVE"));
            assertFalse(httpRequest.isUserInRole("Simulcast"));
            assertEquals("cfloersch", httpRequest.getRemoteUser());
            assertEquals("AUTH_TKT", httpRequest.getAuthType());
            assertEquals("Chris+Floersch", httpRequest.getAttribute("TKTAuthUserData"));
            return null;
         }
      }).when(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

      objectUnderTestWorkbook.doFilter(request, response, chain);

      verify(chain, times(1)).doFilter(any(ServletRequest.class), any(ServletResponse.class));
   }

   @Test
   public void testValidWorkbookAndSimulcastCase() throws ServletException, IOException
   {
      when(cookie.getName()).thenReturn("auth_tkt");
      when(cookie.getValue()).thenReturn("e400af8d8448df14b22193dfdcebe22b55ce64a9cfloersch%21Workbook%2BOVE%21Chris%2BFloersch");

      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      when(request.getScheme()).thenReturn("https");
      when(request.getHeader(eq("Host"))).thenReturn("simulcast.manheim.com");

      doAnswer(new Answer() {
         @Override
         public Object answer(InvocationOnMock invocation)
            throws Throwable
         {
            HttpServletRequest httpRequest = (HttpServletRequest) invocation.getArguments()[0];
            assertTrue(httpRequest.isUserInRole("Workbook+OVE"));
            assertFalse(httpRequest.isUserInRole("Simulcast"));
            assertEquals("cfloersch", httpRequest.getRemoteUser());
            assertEquals("AUTH_TKT", httpRequest.getAuthType());
            assertEquals("Chris+Floersch", httpRequest.getAttribute("TKTAuthUserData"));
            return null;
         }
      }).when(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

      objectUnderTestAll.doFilter(request, response, chain);

      verify(chain, times(1)).doFilter(any(ServletRequest.class), any(ServletResponse.class));
   }


   @Test
   public void testInvalidSimulcastCase() throws ServletException, IOException
   {
      when(cookie.getName()).thenReturn("auth_tkt");
      when(cookie.getValue()).thenReturn("e400af8d8448df14b22193dfdcebe22b55ce64a9cfloersch%21Workbook%2BOVE%21Chris%2BFloersch");

      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      when(request.getScheme()).thenReturn("https");
      when(request.getHeader(eq("Host"))).thenReturn("simulcast.manheim.com");


      objectUnderTestSimulcast.doFilter(request, response, chain);

      verify(response, times(1)).setHeader(eq("Location"), eq("https://www.manheim.com/login?type=role&back=" +
            NetUtils.urlEncode("https://simulcast.manheim.com/simulcast/showBuyerSales.do?filter=AAA")));
      verify(response, times(1)).setStatus(eq(HttpServletResponse.SC_FOUND));
      verify(chain, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));
   }


}