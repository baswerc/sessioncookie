package org.baswell.sessioncookie;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.regex.PatternSyntaxException;

/**
 * Responsible for setting up a {@link HttpServletRequest} with a {@link javax.servlet.http.HttpSession} backed by client cookies.
 */
public class SessionCookieRequestHandler
{
  private final CacheManager cacheManager;

  private final SessionCookieParameters parameters;

  private final SessionCookieErrorHandler errorHandler;

  public SessionCookieRequestHandler(SessionCookieParameters parameters, SessionCookieErrorHandler errorHandler) throws GeneralSecurityException, PatternSyntaxException
  {
    this.parameters = parameters;
    this.errorHandler= errorHandler;
    cacheManager = new CacheManager(parameters, errorHandler);
  }

  /**
   * Sets up the given request with a session backed by client cookies and continues the request pipeline by calling {@link SessionCookieRequestChain#forward(HttpServletRequest, HttpServletResponse)}. This
   * method should be called earlier in the request pipeline.
   *
   * @param request The HTTP request
   * @param response The HTTP response
   * @param chain The request chain processor used to forward the request down the request pipeline
   * @throws IOException
   * @throws ServletException
   */
  public void handle(HttpServletRequest request, HttpServletResponse response, SessionCookieRequestChain chain) throws IOException, ServletException
  {
    RequestWrapper requestWrapper = new RequestWrapper(request, cacheManager);
    chain.forward(requestWrapper, response);
    CookieBackedSession session = requestWrapper.cookieBackedSession;
    if (session == null)
    {
      if (sessionCookieExists(request) && parameters.getInactivityTimeoutSeconds() > 0)
      {
        session = cacheManager.getSession(request, false);
        if (session != null)
        {
          addSessionCookie(session, response);
        }
        else
        {
          removeSessionCookie(request, response);
        }
      }
    }
    else if (session.invalidated)
    {
      removeSessionCookie(request, response);
    }
    else if (session.sessionChanged || parameters.getInactivityTimeoutSeconds() > 0)
    {
      addSessionCookie(session, response);
    }
  }

  private boolean sessionCookieExists(HttpServletRequest request)
  {
    Cookie[] cookies = request.getCookies();
    if (cookies != null)
    {
      String cookieName = parameters.getCookieName();
      for (Cookie cookie : cookies)
      {
        if (cookie.getName().equals(cookieName))
        {
          return true;
        }
      }
    }
    return false;
  }

  private void addSessionCookie(CookieBackedSession session, HttpServletResponse response)
  {
    session.touch();
    try
    {
      String cookieValue = EncodedEncryptedCookieValue.encodeAndEncrypt(session.controlData.encode(), session.sessionData.encode(), parameters.getSymmetricEncryptionKey(), parameters.getSymmetricEncryptionAlgorithm());
      if (cookieValue.length() >= parameters.getCookieSizeWarning())
      {
        errorHandler.onSessionCookieSizeWarning(session, cookieValue.length());
      }
      Cookie cookie = new Cookie(parameters.getCookieName(), cookieValue);
      cookie.setMaxAge(-1);
      String domain = parameters.getCookieDomain();
      if (domain != null && !domain.isEmpty())
      {
        cookie.setDomain(domain);
      }

      response.addCookie(cookie);
    }
    catch (GeneralSecurityException exception)
    {
      errorHandler.onGeneralSecurityException(exception, parameters, true);
    }
  }

  private void removeSessionCookie(HttpServletRequest request, HttpServletResponse response)
  {
    Cookie[] cookies = request.getCookies();
    if (cookies != null)
    {
      String cookieName = parameters.getCookieName();
      for (Cookie cookie : cookies)
      {
        if (cookie.getName().equals(cookieName))
        {
          cookie.setValue(null);
          cookie.setMaxAge(0);
          response.addCookie(cookie);
          break;
        }
      }
    }
  }
}
