package xpertss.auth.tkt;

import org.junit.Before;
import org.junit.Test;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AuthTicketRegexTest {

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
      when(request.getRemoteAddr()).thenReturn("192.168.1.12");
      when(request.getScheme()).thenReturn("https");
      when(request.getHeader(eq("Host"))).thenReturn("www.manheim.com");

      response = mock(HttpServletResponse.class);

      FilterConfig config = mock(FilterConfig.class);
      when(config.getInitParameter(eq("TKTAuthSecret"))).thenReturn("some_random_secret_key");
      when(config.getInitParameter(eq("TKTUrlPattern"))).thenReturn("^/(?!version|health).*");
      when(config.getInitParameter(eq("TKTAuthIgnoreIP"))).thenReturn("on");  // Exclude source IP
      when(config.getInitParameter(eq("TKTAuthTimeout"))).thenReturn("0");    // No timeout
      when(config.getInitParameter(eq("TKTAuthLoginURL"))).thenReturn("https://www.manheim.com/login");

      objectUnderTest = new AuthTicketFilter();
      objectUnderTest.init(config);

      cookie = mock(Cookie.class);
      chain = mock(FilterChain.class);
   }


   @Test
   public void testUrlPatternMatches() throws Exception
   {
      when(request.getRequestURI()).thenReturn("/listings/unassigned");
      objectUnderTest.doFilter(request, response, chain);
      verify(response, times(1)).setStatus(eq(HttpServletResponse.SC_FOUND));
      verify(chain, never()).doFilter(eq(request), eq(response));
   }

   @Test
   public void testUrlPatternFailsToMatchOnVersion() throws Exception
   {
      when(request.getRequestURI()).thenReturn("/version");
      objectUnderTest.doFilter(request, response, chain);
      verify(chain, times(1)).doFilter(eq(request), eq(response));
   }

   @Test
   public void testUrlPatternFailsToMatchOnHealth() throws Exception
   {
      when(request.getRequestURI()).thenReturn("/health");
      objectUnderTest.doFilter(request, response, chain);
      verify(chain, times(1)).doFilter(eq(request), eq(response));
   }

}
