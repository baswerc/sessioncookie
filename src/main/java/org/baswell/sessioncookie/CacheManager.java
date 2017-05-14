package org.baswell.sessioncookie;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static org.baswell.sessioncookie.CookieBackedSession.SESSION_ID_KEY;

class CacheManager implements Runnable
{
  private final SessionCookieParameters parameters;

  private final SessionCookieErrorHandler errorHandler;

  private final Map<String, CookieBackedSession> cache = new ConcurrentHashMap<>();

  private final ReentrantReadWriteLock readWriteLock = new ReentrantReadWriteLock();

  private final ReentrantReadWriteLock.ReadLock readLock = readWriteLock.readLock();

  private final ReentrantReadWriteLock.WriteLock writeLock = readWriteLock.writeLock();

  private volatile Thread backgroundThread;

  private long lastCleanedAt;

  private volatile boolean cleaning;

  public CacheManager(SessionCookieParameters parameters, SessionCookieErrorHandler errorHandler)
  {
    this.parameters = parameters;
    this.errorHandler = errorHandler;
  }

  CookieBackedSession getSession(HttpServletRequest request, boolean createNewIfNecessary)
  {
    boolean usePool = useCache();

    if (usePool)
    {
      if (parameters.getPurgeSessionCacheWithBackgroundThread())
      {
        startIfNecessary();
      }
      else
      {
        purgeIfNecessary();
      }
    }

    String cookieValue = null;
    Cookie[] cookies = request.getCookies();
    if (cookies != null)
    {
      String cookieName = parameters.getCookieName();
      for (Cookie cookie : cookies)
      {
        if (cookie.getName().equalsIgnoreCase(cookieName))
        {
          cookieValue = cookie.getValue();
          break;
        }
      }
    }

    if (cookieValue != null)
    {
      readLock.lock();
      try
      {
        EncodedEncryptedCookieValue encodedEncryptedCookieValue = EncodedEncryptedCookieValue.decodeAndDecrypt(cookieValue, parameters.getSymmetricEncryptionKey(), parameters.getSymmetricEncryptionAlgorithm());
        try
        {
          EncodedMap controlData = new EncodedMap(encodedEncryptedCookieValue.controlData);

          try
          {
            CookieBackedSession session;
            if (usePool)
            {
              String sessionId = (String)controlData.get(SESSION_ID_KEY);
              session = cache.get(sessionId);
              if (session == null)
              {
                session = new CookieBackedSession(controlData, new EncodedMap(encodedEncryptedCookieValue.sessionData));
              }
            }
            else
            {
              session = new CookieBackedSession(controlData, new EncodedMap(encodedEncryptedCookieValue.sessionData));
            }

            if (session.hasExpired(parameters.getSessionTimeoutMinutes()))
            {
              session = null;
              if (usePool)
              {
                cache.remove(session.getId());
              }
            }
            else
            {
              if (usePool && !cache.containsKey(session.getId()))
              {
                cache.put(session.getId(), session);
              }
              return session;
            }
          }
          catch (ClassNotFoundException exception)
          {
            errorHandler.onClassNotFoundFromSessionException(exception);
          }

        }
        catch (ClassNotFoundException exception)
        {
          throw new RuntimeException(exception);
        }
      }
      catch (GeneralSecurityException e)
      {
        errorHandler.onGeneralSecurityException(e, parameters, false);
      }
      catch (SessionCookieDecryptionException e)
      {
        errorHandler.onCookieDecryptError(e);
      }
      catch (SessionCookieDecodingException e)
      {
        errorHandler.onCookieDecodeError(e);
      }
      finally
      {
        readLock.unlock();
      }
    }

    if (createNewIfNecessary)
    {
      CookieBackedSession session = new CookieBackedSession(parameters.getInactivityTimeoutSeconds());
      if (usePool)
      {
        cache.put(session.getId(), session);
      }
      return session;
    }
    else
    {
      return null;
    }
  }

  void purgeIfNecessary()
  {
    int secondsSinceLastClean = (int)((System.currentTimeMillis() - lastCleanedAt) / 1000l);
    if (!cleaning && secondsSinceLastClean < parameters.getMinimumSecondsBetweenSessionCachePurges())
    {
      boolean clean = false;
      synchronized (this)
      {
        if (!cleaning && secondsSinceLastClean < parameters.getMinimumSecondsBetweenSessionCachePurges())
        {
          cleaning = true;
          clean = true;
        }
      }

      if (clean)
      {
        try
        {
          purge();
        }
        finally
        {
          cleaning = false;
          lastCleanedAt = System.currentTimeMillis();
        }
      }
    }
  }

  synchronized void purge()
  {
    if (!useCache())
    {
      if (!cache.isEmpty())
      {
        writeLock.lock();
        try
        {
          cache.clear();
        }
        finally
        {
          writeLock.unlock();
        }
      }
    }
    else
    {
      List<String> expiredSessionIds = new ArrayList<>();
      int maxSessionMinutes = parameters.getSessionTimeoutMinutes();
      for (CookieBackedSession session : cache.values())
      {
        if (session.hasExpired(maxSessionMinutes))
        {
          expiredSessionIds.add(session.getId());
        }
      }

      writeLock.lock();
      try
      {
        for (String expiredSessionId : expiredSessionIds)
        {
          cache.remove(expiredSessionId);
        }
      } finally
      {
        writeLock.unlock();
      }

      int maxSize = parameters.getMaxInMemorySessions();
      if (maxSize >= 0)
      {
        int numberSessionsToRemove = cache.size() - maxSize;
        if (numberSessionsToRemove > 0)
        {
          List<CookieBackedSession> sessionsToRemove = new ArrayList<>();
          for (CookieBackedSession session : cache.values())
          {
            if (sessionsToRemove.size() < numberSessionsToRemove)
            {
              sessionsToRemove.add(session);
            }
            else
            {
              for (int i = 0; i < sessionsToRemove.size(); i++)
              {
                if (sessionsToRemove.get(i).getLastAccessedAt() > session.getLastAccessedAt())
                {
                  sessionsToRemove.set(i, session);
                  break;
                }
              }
            }
          }

          writeLock.lock();
          try
          {
            for (CookieBackedSession session : sessionsToRemove)
            {
              cache.remove(session.getId());
            }
          } finally
          {
            writeLock.unlock();
          }
        }
      }
    }
  }

  void startIfNecessary()
  {
    if (useCache() && backgroundThread == null)
    {
      synchronized (this)
      {
        if (backgroundThread == null && !backgroundThread.isAlive())
        {
          backgroundThread = new Thread(this, "SessionCookie Session Cleander");
          backgroundThread.start();
        }
      }
    }
  }

  boolean useCache()
  {
    return parameters.getMaxInMemorySessions() > 0;
  }

  @Override
  public void run()
  {
    while (backgroundThread == Thread.currentThread() && parameters.getPurgeSessionCacheWithBackgroundThread() && useCache())
    {
      purge();
      try
      {
        Thread.sleep(parameters.getMinimumSecondsBetweenSessionCachePurges() * 1000l);
      }
      catch (Exception e)
      {}
    }
  }
}
