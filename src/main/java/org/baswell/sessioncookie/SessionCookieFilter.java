package org.baswell.sessioncookie;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;

import static java.lang.String.format;
import static org.baswell.sessioncookie.SharedMethods.hasContent;

/**
 *
 * <p>
 *  Used to setup HTTP requests with sessions backed by client cookies. This filter should be placed first in your filter chain (or at least
 *  before an calls to {@link HttpServletRequest#getSession()} are made). The following initialization parameters are supported by this filter.
 * </p>
 *
 * <h3>SessionCookieParametersClassName</h3>
 * <p>
 *  The full qualified class name of the object that implements {@link SessionCookieParameters}. This class must have a default, public constructor
 *  that will be used to initialize a singleton object. It this parameter is not specified then the particular SessionCookie parameters specified below will be used. Example:
 * </p>
 * <pre>
 * {@code
 * <init-param>
 *   <param-name>SessionCookieParametersClassName</param-name>
 *   <param-value>org.example.MySessionCookieParameters</param-value>
 * </init-param>
 * }
 * </pre>
 * <h3>SessionCookieErrorHandlerClassName</h3>
 * <p>
 *  The full qualified class name of the object that implements {@link SessionCookieErrorHandler}. This class must have a default, public constructor
 *  that will be used to initialize a singleton object. If this parameter is not specified then {@link SessionCookieDefaultErrorHandler} will be used which requires the
 *  SLF4J library to be on the classpath. Example:
 * </p>
 * <pre>
 * {@code
 * <init-param>
 *   <param-name>SessionCookieErrorHandlerClassName</param-name>
 *   <param-value>org.example.MySessionCookieErrorHandler</param-value>
 * </init-param>
 * }
 * </pre>
 *
 * <h3>SessionTimeoutMinutes</h3>
 * <p>
 *  The time, in minutes, from creation time that sessions are allowed to remain active. A negative time indicates the session should never timeout. This parameter is only used if <code>SessionCookieParametersClassName</code>
 *  is not specified. The default value for this parameters is {@link SessionCookieParameters#DEFAULT_SESSION_TIMEOUT_MINUTES}. Example:
 * </p>
 * <pre>
 * {@code
 * <init-param>
 *   <param-name>SessionTimeoutMinutes</param-name>
 *   <param-value>-1</param-value>
 * </init-param>
 * }
 * </pre>
 *
 * <h3>InactivityTimeoutSeconds</h3>
 * <p>
 *  The time, in seconds, between client requests that session are allowed to remain active. A negative time indicates the session should never timeout. This parameter is only used if <code>SessionCookieParametersClassName</code>
 *  is not specified. The default value for this parameters is {@link SessionCookieParameters#DEFAULT_INACTIVITY_TIMEOUT_SECONDS}. Example:
 * </p>
 * <pre>
 * {@code
 * <init-param>
 *   <param-name>InactivityTimeoutSeconds</param-name>
 *   <param-value>600</param-value>
 * </init-param>
 * }
 * </pre>
 *
 * <h3>MaxInMemorySessions</h3>
 * <p>
 *  The maximum number of sessions that are cached in memory. A zero or negative value indicates that no sessions are cached. This parameter is only used if <code>SessionCookieParametersClassName</code>
 *  is not specified. The default value for this parameters is {@link SessionCookieParameters#DEFAULT_MAX_IN_MEMORY_SESSIONS}. Example:
 * </p>
 * <pre>
 * {@code
 * <init-param>
 *   <param-name>MaxInMemorySessions</param-name>
 *   <param-value>250</param-value>
 * </init-param>
 * }
 * </pre>
 *
 * <h3>PurgeSessionCacheWithBackgroundThread</h3>
 * <p>
 *  Indicates if a background thread should be used to removed candidates from the session cache. If <code>false</code> sessions will be removed from the cache on request threads.  This parameter is only used if <code>SessionCookieParametersClassName</code>
 *  is not specified and <code>MaxInMemorySessions</code> is greater than zero. The default value for this parameters is {@link SessionCookieParameters#DEFAULT_PURGE_SESSION_CACHE_WITH_BACKGROUND_THREAD}. Example:
 * </p>
 * <pre>
 * {@code
 * <init-param>
 *   <param-name>PurgeSessionCacheWithBackgroundThread</param-name>
 *   <param-value>true</param-value>
 * </init-param>
 * }
 * </pre>
 *
 * <h3>MinimumSecondsBetweenSessionCachePurge</h3>
 * <p>
 *  The minimum number of seconds between session cache purges. This parameter is only used if <code>SessionCookieParametersClassName</code>
 *  is not specified and <code>MaxInMemorySessions</code> is greater than zero. The default value for this parameters is {@link SessionCookieParameters#DEFAULT_MAX_IN_MEMORY_SESSIONS}. Example:
 * </p>
 * <pre>
 * {@code
 * <init-param>
 *   <param-name>MinimumSecondsBetweenSessionCachePurge</param-name>
 *   <param-value>25</param-value>
 * </init-param>
 * }
 * </pre>
 *
 * <h3>SymmetricEncryptionAlgorithm</h3>
 * <p>
 *  The symmetric encryption algorithm used to encrypt and decrypt the session cookie. This parameter is only used if <code>SessionCookieParametersClassName</code>
 *  is not specified. The default value for this parameters is {@link SessionCookieParameters#DEFAULT_SYMMETRIC_ENCRYPTION_ALGORITHM}. Example:
 * </p>
 * <pre>
 * {@code
 * <init-param>
 *   <param-name>SymmetricEncryptionAlgorithm</param-name>
 *   <param-value>AES</param-value>
 * </init-param>
 * }
 * </pre>
 *
 * <h3>SymmetricEncryptionKey</h3>
 * <p>
 *  The Base64 encoded symmetric encryption key used to encrypt and decrypt the session cookie. This parameter is only used if <code>SessionCookieParametersClassName</code>
 *  is not specified. Example:
 * </p>
 * <pre>
 * {@code
 * <init-param>
 *   <param-name>SymmetricEncryptionKey</param-name>
 *   <param-value>Wi2HOOf7B/5kGMnccsodpYPB6xhDFD0AbKTx1gX3Vb8=</param-value>
 * </init-param>
 * }
 * </pre>
 *
 * <h3>CookieDomain</h3>
 * <p>
 *  The domain set ({@link javax.servlet.http.Cookie#setDomain(String)}) on the session cookie. This parameter is only used if <code>SessionCookieParametersClassName</code>
 *  is not specified. Example:
 * </p>
 * <pre>
 * {@code
 * <init-param>
 *   <param-name>CookieDomain</param-name>
 *   <param-value>com.domain.</param-value>
 * </init-param>
 * }
 * </pre>
 *
 * <h3>CookieName</h3>
 * <p>
 *  The name used for the session cookie. This parameter is only used if <code>SessionCookieParametersClassName</code>  is not specified. Example:
 * </p>
 * <pre>
 * {@code
 * <init-param>
 *   <param-name>CookieName</param-name>
 *   <param-value>MySession</param-value>
 * </init-param>
 * }
 * </pre>
 *
 * <h3>CookieSizeWarning</h3>
 * <p>
 *  The minimum session cookie value size in bytes for {@link SessionCookieErrorHandler#onSessionCookieSizeWarning(HttpSession, int)} to be called. This parameter is only used if <code>SessionCookieParametersClassName</code>  is not specified. Example:
 * </p>
 * <pre>
 * {@code
 * <init-param>
 *   <param-name>CookieSizeWarning</param-name>
 *   <param-value>2048</param-value>
 * </init-param>
 * }
 * </pre>
 *
 * <p>
 * If you have HTTP requests that are not accessing {@link javax.servlet.http.HttpSession} there are two parameters you can specify to improve the performance of this filter.
 * </p>
 * <pre>
 * {@code
 * <init-param>
 *   <param-name>OnlyPaths</param-name>
 *   <param-value>/api/.*,/routes/.*</param-value>
 * </init-param>
 * }
 * </pre>
 *
 * <p>
 * The <status>OnlyPaths</status> parameter must be a list (comma delimited) of valid Java regular expression. If specified, only request URIs that match
 * this pattern will be updated to support session cookies. The other supported parameter is <code>ExceptPaths</code>:
 * </p>
 *
 * <pre>
 * {@code
 * <init-param>
 *   <param-name>ExceptPaths</param-name>
 *   <param-value>/img/*,/css/.*,/js/.*</param-value>
 * </init-param>
 * }
 * </pre>
 *
 * <p>
 * The <code>ExceptPaths</code> parameter must be a list (comma delimited) of valid Java regular expression. If specified, all request URIs that match this pattern will not be updated to support session cookies. If both <code>ONLY</code> and <code>ExceptPaths</code> are specified
 * then request will not be updated to support session cookies if the <code>OnlyPaths</code> pattern does not match or the <code>ExceptPaths</code> pattern does match.
 * </p> */
public class SessionCookieFilter implements Filter
{
  static final String PARAMETERS_CLASS_NAME = "SessionCookieParametersClassName";

  static final String ERROR_HANDLER_CLASS_NAME = "SessionCookieErrorHandlerClassName";

  static final String SESSION_TIMEOUT_MINUTES = "SessionTimeoutMinutes";

  static final String INACTIVITY_TIMEOUT_SECONDS = "InactivityTimeoutSeconds";

  static final String MAX_IN_MEMORY_SESSIONS = "MaxInMemorySessions";

  static final String PURGE_SESSION_CACHE_WITH_BACKGROUND_THREAD = "PurgeSessionCacheWithBackgroundThread";

  static final String MINIMUM_SECONDS_BETWEEN_SESSION_CACHE_PURGES = "MinimumSecondsBetweenSessionCachePurge";

  static final String SYMMETRIC_ENCRYPTION_ALGORITHM = "SymmetricEncryptionAlgorithm";

  static final String SYMMETRIC_ENCRYPTION_KEY = "SymmetricEncryptionKey";

  static final String COOKIE_DOMAIN = "CookieDomain";

  static final String COOKIE_NAME = "CookieName";

  static final String COOKIE_SIZE_WARNING = "CookieSizeWarning";

  static final String ONLY_PATHS = "OnlyPaths";

  static final String EXCLUDED_PATHS = "ExcludedPaths";

  private List<Pattern> includedPaths;

  private List<Pattern> excludedPaths;

  private SessionCookieRequestHandler processor;

  @Override
  public void init(FilterConfig filterConfig) throws ServletException
  {
    SessionCookieParameters parameters = null;
    SessionCookieErrorHandler errorHandler = null;

    String parametersClassName = filterConfig.getInitParameter(PARAMETERS_CLASS_NAME);
    if (hasContent(parametersClassName))
    {
      try
      {
        Class clazz = Class.forName(parametersClassName);
        parameters = (SessionCookieParameters) clazz.newInstance();
      }
      catch (ClassNotFoundException | IllegalAccessException | InstantiationException | ClassCastException e)
      {
        throw new ServletException(format("Invalid %s parameter %s.", PARAMETERS_CLASS_NAME, parametersClassName), e);
      }
    }

    String errorHandlerClassName = filterConfig.getInitParameter(ERROR_HANDLER_CLASS_NAME);
    if (hasContent(parametersClassName))
    {
      try
      {
        Class clazz = Class.forName(errorHandlerClassName);
        errorHandler = (SessionCookieErrorHandler) clazz.newInstance();
      }
      catch (ClassNotFoundException | IllegalAccessException | InstantiationException | ClassCastException e)
      {
        throw new ServletException(format("Invalid %s parameter %s.", ERROR_HANDLER_CLASS_NAME, errorHandlerClassName), e);
      }
    }

    if (parameters == null)
    {
      SessionCookieDefaultParameters defaultParmaters = new SessionCookieDefaultParameters();
      parameters = defaultParmaters;

      String sessionTimeoutMinutesParam = filterConfig.getInitParameter(SESSION_TIMEOUT_MINUTES);
      if (hasContent(sessionTimeoutMinutesParam))
      {
        defaultParmaters.setSessionTimeoutMinutes(parseParameter(SESSION_TIMEOUT_MINUTES, sessionTimeoutMinutesParam));
      }

      String inactivityTimeoutSecondsParam = filterConfig.getInitParameter(INACTIVITY_TIMEOUT_SECONDS);
      if (hasContent(inactivityTimeoutSecondsParam))
      {
        defaultParmaters.setInactivityTimeoutSeconds(parseParameter(INACTIVITY_TIMEOUT_SECONDS, inactivityTimeoutSecondsParam));
      }

      String maxInMemorySessionsParam = filterConfig.getInitParameter(MAX_IN_MEMORY_SESSIONS);
      if (hasContent(maxInMemorySessionsParam))
      {
        defaultParmaters.setMaxInMemorySessions(parseParameter(MAX_IN_MEMORY_SESSIONS, maxInMemorySessionsParam));
      }

      String useBackgroundThread = filterConfig.getInitParameter(PURGE_SESSION_CACHE_WITH_BACKGROUND_THREAD);
      if (hasContent(useBackgroundThread))
      {
        defaultParmaters.setPurgeSessionCacheWithBackgroundThread(Boolean.parseBoolean(useBackgroundThread));
      }

      String cleanPollSecondsParam = filterConfig.getInitParameter(MINIMUM_SECONDS_BETWEEN_SESSION_CACHE_PURGES);
      if (hasContent(cleanPollSecondsParam))
      {
        defaultParmaters.setMinimumSecondsBetweenSessionCachePurges(parseParameter(MINIMUM_SECONDS_BETWEEN_SESSION_CACHE_PURGES, cleanPollSecondsParam));
      }

      String encryptionSymmetricAlgorithm = filterConfig.getInitParameter(SYMMETRIC_ENCRYPTION_ALGORITHM);
      if (hasContent(encryptionSymmetricAlgorithm))
      {
        defaultParmaters.setSymmetricEncryptionAlgorithm(encryptionSymmetricAlgorithm);
      }

      String encryptionKeyParameter = filterConfig.getInitParameter(SYMMETRIC_ENCRYPTION_KEY);
      if (hasContent(encryptionKeyParameter))
      {
        try
        {
          defaultParmaters.setSymmetricEncryptionKey(Base64.getDecoder().decode(encryptionKeyParameter));
        }
        catch (Exception e)
        {
          throw new ServletException(format("Invalid %s parameter %s.", SYMMETRIC_ENCRYPTION_KEY, encryptionKeyParameter), e);
        }
      }

      String cookieDomain = filterConfig.getInitParameter(COOKIE_DOMAIN);
      if (hasContent(cookieDomain))
      {
        defaultParmaters.setCookieDomain(cookieDomain);
      }

      String cookieName = filterConfig.getInitParameter(COOKIE_NAME);
      if (hasContent(cookieName))
      {
        defaultParmaters.setCookieName(cookieName);
      }

      String cookieSizeWarning = filterConfig.getInitParameter(COOKIE_SIZE_WARNING);
      if (hasContent(cookieSizeWarning))
      {
        defaultParmaters.setCookieSizeWarning(parseParameter(COOKIE_SIZE_WARNING, cookieSizeWarning));
      }
    }

    try
    {
      EncodedEncryptedCookieValue.encodeAndEncrypt("A", "B", parameters.getSymmetricEncryptionKey(), parameters.getSymmetricEncryptionAlgorithm());
    }
    catch (Exception e)
    {
      throw new ServletException(format("Unable to encrypt using provided algorithm %s and key.", parameters.getSymmetricEncryptionAlgorithm()), e);
    }

    if (errorHandler == null)
    {
      errorHandler = new SessionCookieDefaultErrorHandler();
    }

    includedPaths = null;
    String includedPathsParams = filterConfig.getInitParameter(ONLY_PATHS);
    if (hasContent(includedPathsParams))
    {
      includedPaths = new ArrayList<>();
      String[] paths = includedPathsParams.split(",");
      for (String path : paths)
      {
        if (hasContent(path))
        {
          try
          {
            includedPaths.add(Pattern.compile(path));
          }
          catch (Exception e)
          {
            throw new ServletException(format("Invalid included paths pattern %s for parameter %s.", path, includedPathsParams), e);
          }
        }
      }
    }

    excludedPaths = null;
    String excludedPathsParams = filterConfig.getInitParameter(EXCLUDED_PATHS);
    if (hasContent(includedPathsParams))
    {
      excludedPaths = new ArrayList<>();
      String[] paths = excludedPathsParams.split(",");
      for (String path : paths)
      {
        if (hasContent(path))
        {
          try
          {
            excludedPaths.add(Pattern.compile(path));
          }
          catch (Exception e)
          {
            throw new ServletException(format("Invalid excluded paths pattern %s for parameter %s.", path, excludedPathsParams), e);
          }
        }
      }
    }

    try
    {
      processor = new SessionCookieRequestHandler(parameters, errorHandler);
    }
    catch (GeneralSecurityException e)
    {
      throw new ServletException(e);
    }
  }

  @Override
  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException
  {
    HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
    if (wrapRequest(httpRequest.getContextPath(), httpRequest.getRequestURI(), includedPaths, excludedPaths))
    {
      processor.handle(httpRequest, (HttpServletResponse) servletResponse, new SessionCookieFilterRequestChain(filterChain));
    }
    else
    {
      filterChain.doFilter(servletRequest, servletResponse);
    }
  }

  @Override
  public void destroy()
  {}

  static int parseParameter(String parameterName, String parameterValue) throws ServletException
  {
    try
    {
      return Integer.parseInt(parameterValue);
    }
    catch (NumberFormatException e)
    {
      throw new ServletException(format("Invalid %s parameter %s.", parameterName, parameterValue), e);
    }
  }

  static boolean wrapRequest(String contextPath, String requestPath, List<Pattern> onlyPatterns, List<Pattern> exceptPatterns)
  {
    if (requestPath.startsWith(contextPath))
    {
      requestPath = requestPath.substring(contextPath.length(), requestPath.length());
    }

    if (onlyPatterns != null || exceptPatterns != null)
    {
      if (onlyPatterns != null)
      {
        boolean matchFound = false;
        for (Pattern onlyPattern : onlyPatterns)
        {
          if (onlyPattern.matcher(requestPath).matches())
          {
            matchFound = true;
            break;
          }
        }

        if (!matchFound)
        {
          return false;
        }
      }

      if (exceptPatterns != null)
      {
        for (Pattern exceptPattern : exceptPatterns)
        {
          if (exceptPattern.matcher(requestPath).matches())
          {
            return false;
          }
        }
      }
    }

    return true;
  }
}
