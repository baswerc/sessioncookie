package org.baswell.sessioncookie;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * A {@link SessionCookieRequestChain} for {@link javax.servlet.Filter}.
 */
public class SessionCookieFilterRequestChain implements SessionCookieRequestChain
{
  private final FilterChain filterChain;

  public SessionCookieFilterRequestChain(FilterChain filterChain)
  {
    this.filterChain = filterChain;
  }

  @Override
  public void forward(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
  {
    filterChain.doFilter(request, response);
  }
}
