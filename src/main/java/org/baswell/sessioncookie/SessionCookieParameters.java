package org.baswell.sessioncookie;

import javax.servlet.http.HttpSession;
import java.security.GeneralSecurityException;

/**
 * All parameters used by SessionCookie. These parameters are not cached and will be called on HTTP request threads. It's important that each of these methods
 * return immediately (no IO blocking) or request performance will be impacted.
 */
public interface SessionCookieParameters
{
  /**
   * <code>30</code>
   */
  int DEFAULT_SESSION_TIMEOUT_MINUTES = 30;

  /**
   * <code>-1</code>
   */
  int DEFAULT_INACTIVITY_TIMEOUT_SECONDS = -1;

  /**
   * <code>-1</code>
   */
  int DEFAULT_MAX_IN_MEMORY_SESSIONS = -1;

  /**
   * <code>false</code>
   */
  boolean DEFAULT_PURGE_SESSION_CACHE_WITH_BACKGROUND_THREAD = false;

  /**
   * <code>15</code>
   */
  int DEFAULT_MINIMUM_SECONDS_BETWEEN_SESSION_CACHE_PURGES = 15;

  /**
   * <code>AES</code>
   */
  String DEFAULT_SYMMETRIC_ENCRYPTION_ALGORITHM = "AES";

  /**
   * <code>null</code>
   */
  String DEFAULT_COOKIE_DOMAIN = null;

  /**
   * <code>org.baswell.sessioncookie</code>
   */
  String DEFAULT_COOKIE_NAME = "org.baswell.sessioncookie";

  /**
   * 4KB
   */
  int DEFAULT_COOKIE_SIZE_WARNING = 1024 * 4;


  /**
   * The time, in minutes, from creation time that sessions are allowed to remain active. A negative time indicates the session should never timeout.
   * @return {@link SessionCookieParameters#DEFAULT_SESSION_TIMEOUT_MINUTES} by default
   */
  default int getSessionTimeoutMinutes()
  {
    return DEFAULT_SESSION_TIMEOUT_MINUTES;
  }

  /**
   * The time, in seconds, between client requests that session are allowed to remain active. A negative time indicates the session should never timeout.
   * @return {@link SessionCookieParameters#DEFAULT_INACTIVITY_TIMEOUT_SECONDS} by default
   */
  default int getInactivityTimeoutSeconds()
  {
    return DEFAULT_INACTIVITY_TIMEOUT_SECONDS;
  }

  /**
   * The maximum number of sessions that are cached in memory. A zero or negative value indicates that no sessions are cached.
   * @return {@link SessionCookieParameters#DEFAULT_MAX_IN_MEMORY_SESSIONS} by default
   */
  default int getMaxInMemorySessions()
  {
    return DEFAULT_MAX_IN_MEMORY_SESSIONS;
  }

  /**
   * Indicates if a background thread should be used to removed candidates from the session cache. If <code>false</code> sessions will be removed from the cache on request threads.
   * @return {@link SessionCookieParameters#DEFAULT_PURGE_SESSION_CACHE_WITH_BACKGROUND_THREAD} by default
   */
  default boolean getPurgeSessionCacheWithBackgroundThread()
  {
    return DEFAULT_PURGE_SESSION_CACHE_WITH_BACKGROUND_THREAD;
  }

  /**
   * The minimum number of seconds between session cache purges.
   * @return {@link SessionCookieParameters#DEFAULT_MINIMUM_SECONDS_BETWEEN_SESSION_CACHE_PURGES} by default
   */
  default int getMinimumSecondsBetweenSessionCachePurges()
  {
    return DEFAULT_MINIMUM_SECONDS_BETWEEN_SESSION_CACHE_PURGES;
  }

  /**
   * The symmetric encryption algorithm used to encrypt and decrypt the session cookie.
   * @return {@link SessionCookieParameters#DEFAULT_SYMMETRIC_ENCRYPTION_ALGORITHM} by default
   */
  default String getSymmetricEncryptionAlgorithm()
  {
    return DEFAULT_SYMMETRIC_ENCRYPTION_ALGORITHM;
  }

  /**
   * The symmetric encryption key used to encrypt and decrypt the session cookie.
   * @return The encoded key value
   * @throws GeneralSecurityException if the key cannot be generated
   */
  byte[] getSymmetricEncryptionKey() throws GeneralSecurityException;

  /**
   * The domain set ({@link javax.servlet.http.Cookie#setDomain(String)}) on the session cookie.
   * @return {@link SessionCookieParameters#DEFAULT_COOKIE_DOMAIN} by default
   */
  default String getCookieDomain()
  {
    return DEFAULT_COOKIE_DOMAIN;
  }

  /**
   * The name used for the session cookie.
   * @return {@link SessionCookieParameters#DEFAULT_COOKIE_NAME} by default
   */
  default String getCookieName()
  {
    return DEFAULT_COOKIE_NAME;
  }

  /**
   * The minimum session cookie value size in bytes for {@link SessionCookieErrorHandler#onSessionCookieSizeWarning(HttpSession, int)} to be called.
   * @return {@link SessionCookieParameters#DEFAULT_COOKIE_SIZE_WARNING} by default
   * @see SessionCookieErrorHandler#onSessionCookieSizeWarning(HttpSession, int)
   */
  default int getCookieSizeWarning()
  {
    return DEFAULT_COOKIE_SIZE_WARNING;
  }
}
