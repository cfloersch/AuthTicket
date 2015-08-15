package xpertss.auth.tkt;

import org.junit.Before;
import org.junit.Test;
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

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Basic use case configures both the timeout url and the authUrl, does not allow guests,
 * does not use tokens, and ignores IP addresses.
 *
 * It is intended to test expires functionality
 */
public class SecondBasicUseCaseTest {

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
      when(request.getRequestURI()).thenReturn("/simulcast/showBuyerSales.do?filter=AAA");
      when(request.getRemoteAddr()).thenReturn("192.168.1.12");

      response = mock(HttpServletResponse.class);

      FilterConfig config = mock(FilterConfig.class);
      when(config.getInitParameter(eq("TKTAuthSecret"))).thenReturn("some_random_secret_key");
      when(config.getInitParameter(eq("TKTAuthIgnoreIP"))).thenReturn("on");  // Exclude source IP
      when(config.getInitParameter(eq("TKTAuthLoginURL"))).thenReturn("https://www.manheim.com/login");
      when(config.getInitParameter(eq("TKTAuthTimeoutURL"))).thenReturn("https://www.manheim.com/login?timeout=1");
      when(config.getInitParameter(eq("TKTAuthPostTimeoutURL"))).thenReturn("https://www.manheim.com/login?timeout=2");

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


      objectUnderTest.doFilter(request, response, chain);

      verify(response, times(1)).sendRedirect(eq("https://www.manheim.com/login?back=" +
         NetUtils.urlEncode("https://simulcast.manheim.com/simulcast/showBuyerSales.do?filter=AAA")));
      verify(chain, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));

   }

   @Test
   public void testMisNamedCookie() throws ServletException, IOException
   {
      when(cookie.getName()).thenReturn("MisNamed");

      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      when(request.getScheme()).thenReturn("https");
      when(request.getHeader(eq("Host"))).thenReturn("simulcast.manheim.com");


      objectUnderTest.doFilter(request, response, chain);

      verify(response, times(1)).sendRedirect(eq("https://www.manheim.com/login?back=" +
         NetUtils.urlEncode("https://simulcast.manheim.com/simulcast/showBuyerSales.do?filter=AAA")));
      verify(chain, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));
   }

   @Test
   public void testEmptyCookie() throws ServletException, IOException
   {
      when(cookie.getName()).thenReturn("auth_tkt");
      when(cookie.getValue()).thenReturn("");

      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      when(request.getScheme()).thenReturn("https");
      when(request.getHeader(eq("Host"))).thenReturn("simulcast.manheim.com");


      objectUnderTest.doFilter(request, response, chain);

      verify(response, times(1)).sendRedirect(eq("https://www.manheim.com/login?back=" +
         NetUtils.urlEncode("https://simulcast.manheim.com/simulcast/showBuyerSales.do?filter=AAA")));
      verify(chain, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));
   }

   @Test
   public void testMalformedCookie() throws ServletException, IOException
   {
      when(cookie.getName()).thenReturn("auth_tkt");
      when(cookie.getValue()).thenReturn("00112233445566778899aabbccddeeff00000000cfloersch");

      when(request.getCookies()).thenReturn(new Cookie[] { cookie });
      when(request.getScheme()).thenReturn("https");
      when(request.getHeader(eq("Host"))).thenReturn("simulcast.manheim.com");


      objectUnderTest.doFilter(request, response, chain);

      verify(response, times(1)).sendRedirect(eq("https://www.manheim.com/login?back=" +
         NetUtils.urlEncode("https://simulcast.manheim.com/simulcast/showBuyerSales.do?filter=AAA")));
      verify(chain, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));
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

      objectUnderTest.doFilter(request, response, chain);

      verify(response, times(1)).sendRedirect(eq("https://www.manheim.com/login?timeout=1&back=" +
         NetUtils.urlEncode("https://simulcast.manheim.com/simulcast/showBuyerSales.do?filter=AAA")));
      verify(chain, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));

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

      objectUnderTest.doFilter(request, response, chain);

      verify(response, times(1)).sendRedirect(eq("https://www.manheim.com/login?timeout=2&back=" +
         NetUtils.urlEncode("https://simulcast.manheim.com/simulcast/showBuyerSales.do?filter=AAA")));
      verify(chain, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));

   }


}