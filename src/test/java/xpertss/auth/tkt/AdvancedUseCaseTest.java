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
 * Test case for the various http proxy headers
 */
public class AdvancedUseCaseTest {

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
      when(config.getInitParameter(eq("TKTAuthTimeout"))).thenReturn("0");    // No timeout
      when(config.getInitParameter(eq("TKTAuthLoginURL"))).thenReturn("https://www.manheim.com/login");

      objectUnderTest = new AuthTicketFilter();
      objectUnderTest.init(config);

      cookie = mock(Cookie.class);
      chain = mock(FilterChain.class);
   }



   @Test
   public void testXForwardedHeaders() throws ServletException, IOException
   {
      when(request.getCookies()).thenReturn(new Cookie[0]);
      when(request.getScheme()).thenReturn("http");
      when(request.getHeader(eq("X-Forwarded-Proto"))).thenReturn("https");
      when(request.getHeader(eq("Host"))).thenReturn("sim-dc3prod-web01.imanheim.com");
      when(request.getHeader(eq("X-Forwarded-Host"))).thenReturn("simulcast.manheim.com");


      objectUnderTest.doFilter(request, response, chain);

      verify(response, times(1)).setHeader(eq("Location"), eq("https://www.manheim.com/login?back=" +
         NetUtils.urlEncode("https://simulcast.manheim.com/simulcast/showBuyerSales.do?filter=AAA")));
      verify(response, times(1)).setStatus(eq(HttpServletResponse.SC_TEMPORARY_REDIRECT));
      verify(chain, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));

   }

}