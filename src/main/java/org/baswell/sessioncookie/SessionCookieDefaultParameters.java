package org.baswell.sessioncookie;

import javax.crypto.KeyGenerator;
import java.security.GeneralSecurityException;

/**
 * Default parameters used for {@link SessionCookieParameters}.
 */
public class SessionCookieDefaultParameters implements SessionCookieParameters
{
  private int sessionTimeoutMinutes = DEFAULT_SESSION_TIMEOUT_MINUTES;

  private int inactivityTimeoutSeconds = DEFAULT_INACTIVITY_TIMEOUT_SECONDS;

  private int maxInMemorySessions = DEFAULT_MAX_IN_MEMORY_SESSIONS;

  private boolean purgeSessionCacheWithBackgroundThread = DEFAULT_PURGE_SESSION_CACHE_WITH_BACKGROUND_THREAD;

  private int minimumSecondsBetweenSessionCachePurges = DEFAULT_MINIMUM_SECONDS_BETWEEN_SESSION_CACHE_PURGES;

  private volatile byte[] key;

  private String symmetricEncryptionAlgorithm = DEFAULT_SYMMETRIC_ENCRYPTION_ALGORITHM;

  private String cookieDomain = DEFAULT_COOKIE_DOMAIN;

  private String cookieName = DEFAULT_COOKIE_NAME;

  private int cookieSizeWarning = DEFAULT_COOKIE_SIZE_WARNING;

  public void setSessionTimeoutMinutes(int sessionTimeoutMinutes)
  {
    this.sessionTimeoutMinutes = sessionTimeoutMinutes;
  }

  @Override
  public int getSessionTimeoutMinutes()
  {
    return sessionTimeoutMinutes;
  }

  public void setInactivityTimeoutSeconds(int inactivityTimeoutSeconds)
  {
    this.inactivityTimeoutSeconds = inactivityTimeoutSeconds;
  }

  public int getInactivityTimeoutSeconds()
  {
    return inactivityTimeoutSeconds;
  }


  public void setMaxInMemorySessions(int maxInMemorySessions)
  {
    this.maxInMemorySessions = maxInMemorySessions;
  }

  @Override
  public int getMaxInMemorySessions()
  {
    return maxInMemorySessions;
  }

  public void setPurgeSessionCacheWithBackgroundThread(boolean purgeSessionCacheWithBackgroundThread)
  {
    this.purgeSessionCacheWithBackgroundThread = purgeSessionCacheWithBackgroundThread;
  }

  @Override
  public boolean getPurgeSessionCacheWithBackgroundThread()
  {
    return purgeSessionCacheWithBackgroundThread;
  }

  public void setMinimumSecondsBetweenSessionCachePurges(int minimumSecondsBetweenSessionCachePurges)
  {
    this.minimumSecondsBetweenSessionCachePurges = minimumSecondsBetweenSessionCachePurges;
  }

  @Override
  public int getMinimumSecondsBetweenSessionCachePurges()
  {
    return minimumSecondsBetweenSessionCachePurges;
  }

  public void setSymmetricEncryptionAlgorithm(String symmetricEncryptionAlgorithm)
  {
    this.symmetricEncryptionAlgorithm = symmetricEncryptionAlgorithm;
  }

  @Override
  public String getSymmetricEncryptionAlgorithm()
  {
    return symmetricEncryptionAlgorithm;
  }

  public void setSymmetricEncryptionKey(byte[] key)
  {
    this.key = key;
  }

  @Override
  public byte[] getSymmetricEncryptionKey() throws GeneralSecurityException
  {
    if (key == null)
    {
      synchronized (this)
      {
        if (key == null)
        {
          KeyGenerator generator = KeyGenerator.getInstance(getSymmetricEncryptionAlgorithm());
          generator.init(256);
          key = generator.generateKey().getEncoded();
        }
      }
    }

    return key;
  }

  public void setCookieDomain(String cookieDomain)
  {
    this.cookieDomain = cookieDomain;
  }

  @Override
  public String getCookieDomain()
  {
    return cookieDomain;
  }

  public void setCookieName(String cookieName)
  {
    this.cookieName = cookieName;
  }

  @Override
  public String getCookieName()
  {
    return cookieName;
  }

  public void setCookieSizeWarning(int cookieSizeWarning)
  {
    this.cookieSizeWarning = cookieSizeWarning;
  }

  @Override
  public int getCookieSizeWarning()
  {
    return cookieSizeWarning;
  }
}
