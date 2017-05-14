package org.baswell.sessioncookie;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpSession;

class RequestWrapper extends HttpServletRequestWrapper
{
  CookieBackedSession cookieBackedSession;

  private final CacheManager cacheManager;

  RequestWrapper(HttpServletRequest request, CacheManager cacheManager)
  {
    super(request);
    this.cacheManager = cacheManager;
  }

  @Override
  public HttpSession getSession()
  {
    if (cookieBackedSession == null)
    {
      cookieBackedSession = cacheManager.getSession(this, true);
    }
    return cookieBackedSession;
  }
}
