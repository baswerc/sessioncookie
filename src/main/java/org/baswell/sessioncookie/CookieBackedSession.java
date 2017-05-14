package org.baswell.sessioncookie;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionContext;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.UUID;
import java.util.Vector;

import static java.lang.String.format;

class CookieBackedSession implements HttpSession
{
  static final String SESSION_ID_KEY = "sessionId";

  static final String CREATED_AT_KEY = "createdAt";

  static final String LAST_ACCESSED_AT_KEY = "lastAccessedAt";

  static final String SESSION_INACTIVITY_TIMEOUT_KEY = "sessionInactivityTimeout";

  EncodedMap controlData;

  EncodedMap sessionData;

  HttpServletRequest currentRequest;

  boolean newSession;

  boolean sessionChanged;

  boolean invalidated;

  CookieBackedSession(int sessionInactivityTimeoutSeconds)
  {
    newSession = true;

    controlData = new EncodedMap();
    sessionData = new EncodedMap();

    controlData.put(SESSION_ID_KEY, UUID.randomUUID().toString());
    long now = System.currentTimeMillis();
    controlData.put(CREATED_AT_KEY, now);
    controlData.put(LAST_ACCESSED_AT_KEY, now);
    controlData.put(SESSION_INACTIVITY_TIMEOUT_KEY, sessionInactivityTimeoutSeconds);
  }

  CookieBackedSession(EncodedMap controlData, EncodedMap sessionData)
  {
    this.controlData = controlData;
    this.sessionData = sessionData;
  }

  boolean hasExpired(int maxSessionMinutes)
  {
    int minutesSinceCreated = (int)(System.currentTimeMillis() - getCreationTime()) / 1000 / 60;
    if (minutesSinceCreated > maxSessionMinutes)
    {
      return true;
    }
    else
    {
      int maxInactivitySeconds = getMaxInactiveInterval();
      if (maxInactivitySeconds >= 0)
      {
        int secondsSinceLastActivity = (int)(System.currentTimeMillis() - getLastAccessedAt()) / 1000;
        return secondsSinceLastActivity > maxInactivitySeconds;
      }
      else
      {
        return false;
      }
    }
  }

  long getLastAccessedAt()
  {
    return (long) controlData.get(LAST_ACCESSED_AT_KEY);
  }

  void update(HttpServletRequest currentRequest)
  {
    this.currentRequest = currentRequest;
  }

  void update(HttpServletRequest currentRequest, EncodedMap controlData, EncodedMap sessionData)
  {
    update(currentRequest);
    this.controlData = controlData;
    this.sessionData = sessionData;
  }

  void touch()
  {
    controlData.put(LAST_ACCESSED_AT_KEY, System.currentTimeMillis());
  }

  /**
   * Returns a string containing the unique identifier assigned to this session. The identifier is assigned by the servlet container and is implementation dependent.
   * @return a string specifying the identifier assigned to this session
   * @throws java.lang.IllegalStateException - if this method is called on an invalidated session
   */
  @Override
  public String getId()
  {
    return (String)controlData.get(SESSION_ID_KEY);
  }

  /**
   * Returns the time when this session was created, measured in milliseconds since midnight January 1, 1970 GMT.
   * @return a long specifying when this session was created, expressed in milliseconds since 1/1/1970 GMT
   * @throws java.lang.IllegalStateException - if this method is called on an invalidated session
   */
  @Override
  public long getCreationTime()
  {
    return (long) controlData.get(CREATED_AT_KEY);
  }

  /**
   * Returns the last time the client sent a request associated with this session, as the number of milliseconds since midnight January 1, 1970 GMT, and marked by the time the container received the request.
   *
   * Actions that your application takes, such as getting or setting a value associated with the session, do not affect the access time.
   *
   * @return a long representing the last time the client sent a request associated with this session, expressed in milliseconds since 1/1/1970 GMT
   * @throws java.lang.IllegalStateException - if this method is called on an invalidated session
   */
  @Override
  public long getLastAccessedTime()
  {
    return (long) controlData.get(LAST_ACCESSED_AT_KEY);
  }

  /**
   * Returns the object bound with the specified name in this session, or null if no object is bound under the name.
   * @param name - a string specifying the name of the object
   * @return the object with the specified name
   * @throws  java.lang.IllegalStateException - if this method is called on an invalidated session
   */
  @Override
  public Object getAttribute(String name)
  {
    assertValid();
    return sessionData.get(name);
  }


  /**
   * Binds an object to this session, using the name specified. If an object of the same name is already bound to the session, the object is replaced.
   *
   * After this method executes, and if the new object implements HttpSessionBindingListener, the container calls HttpSessionBindingListener.valueBound. The container then notifies any HttpSessionAttributeListeners in the web application.
   *
   * If an object was already bound to this session of this name that implements HttpSessionBindingListener, its HttpSessionBindingListener.valueUnbound method is called.
   *
   * If the value passed in is null, this has the same effect as calling removeAttribute().
   *
   * @param name - the name to which the object is bound; cannot be null
   * @param value - the object to be bound
   * @throws java.lang.IllegalStateException - if this method is called on an invalidated session
   */
  @Override
  public void setAttribute(String name, Object value)
  {
    assertValid();
    if (!(value instanceof Serializable))
    {
      throw new IllegalArgumentException(format("HttpSession.setAttribute called with name %s and non-Serializable value of type %s. Only values of type Serializable are allowed.", name, value.getClass().toString()));
    }

    sessionChanged = true;
    sessionData.put(name, value);
  }

  /**
   * Removes the object bound with the specified name from this session. If the session does not have an object bound with the specified name, this method does nothing.
   *
   * After this method executes, and if the object implements HttpSessionBindingListener, the container calls HttpSessionBindingListener.valueUnbound. The container then notifies any HttpSessionAttributeListeners in the web application.
   * @param name - the name of the object to remove from this session
   * @throws java.lang.IllegalStateException - if this method is called on an invalidated session
   */
  @Override
  public void removeAttribute(String name)
  {
    assertValid();
    if (sessionData.containsKey(name))
    {
      sessionChanged = true;
      sessionData.remove(name);
    }
  }

  /**
   * Returns an Enumeration of String objects containing the names of all the objects bound to this session.
   * @return an Enumeration of String objects specifying the names of all the objects bound to this session
   * @throws java.lang.IllegalStateException - if this method is called on an invalidated session
   */
  @Override
  public Enumeration<String> getAttributeNames()
  {
    assertValid();
    return new Vector<>(sessionData.keySet()).elements();
  }


  /**
   * Returns the maximum time interval, in seconds, that the servlet container will keep this session open between client accesses. After this interval, the servlet container will invalidate the session. The maximum time interval can be set with the setMaxInactiveInterval method. A negative time indicates the session should never timeout.
   * @return an integer specifying the number of seconds this session remains open between client requests
   * @see #setMaxInactiveInterval(int)
   */
  @Override
  public int getMaxInactiveInterval()
  {
    return (int) controlData.get(SESSION_INACTIVITY_TIMEOUT_KEY);
  }

  /**
   * Specifies the time, in seconds, between client requests before the servlet container will invalidate this session. A negative time indicates the session should never timeout.
   *
   * @param interval - An integer specifying the number of seconds
   */
  @Override
  public void setMaxInactiveInterval(int interval)
  {
    controlData.put(SESSION_INACTIVITY_TIMEOUT_KEY, interval);
  }

  /**
   * Returns the ServletContext to which this session belongs.
   * @return The ServletContext object for the web application
   * @since 2.3
   */
  @Override
  public ServletContext getServletContext()
  {
    return currentRequest.getServletContext();
  }

  /**
   * @deprecated  As of Version 2.1, this method is deprecated and has no replacement. It will be removed in a future version of the Java Servlet API.
   */
  @Override
  public HttpSessionContext getSessionContext()
  {
    throw new IllegalStateException("HttpSession.getSessionContext is not supported.");
  }

  /**
   * @deprecated As of Version 2.2, this method is replaced by getAttribute(java.lang.String).
   * @param name - a string specifying the name of the object
   * @return the object with the specified name
   * @throws java.lang.IllegalStateException - if this method is called on an invalidated session
   */
  @Override
  public Object getValue(String name)
  {
    return getAttribute(name);
  }

  /**
   * As of Version 2.2, this method is replaced by setAttribute(java.lang.String, java.lang.Object)
   * @param name - the name to which the object is bound; cannot be null
   * @param value - the object to be bound; cannot be null
   * @throws java.lang.IllegalStateException - if this method is called on an invalidated session
   */
  @Override
  public void putValue(String name, Object value)
  {
    setAttribute(name, value);
  }

  /**
   * @deprecated As of Version 2.2, this method is replaced by getAttributeNames()
   * @return an array of String objects specifying the names of all the objects bound to this session
   * @throws java.lang.IllegalStateException - if this method is called on an invalidated session
   */
  @Override
  public String[] getValueNames()
  {
    Enumeration<String> names = getAttributeNames();
    List<String> list = new ArrayList<>();
    while (names.hasMoreElements())
    {
      list.add(names.nextElement());
    }
    return list.toArray(new String[list.size()]);
  }

  /**
   * @deprecated  As of Version 2.2, this method is replaced by removeAttribute(java.lang.String)
   * @param name - the name of the object to remove from this session
   * @throws java.lang.IllegalStateException - if this method is called on an invalidated session
   */
  @Override
  public void removeValue(String name)
  {
    removeAttribute(name);
  }

  /**
   * Invalidates this session then unbinds any objects bound to it.
   */
  @Override
  public void invalidate()
  {
    invalidated = true;
    sessionData.clear();
  }

  /**
   * Returns true if the client does not yet know about the session or if the client chooses not to join the session. For example, if the server used only cookie-based sessions, and the client had disabled the use of cookies, then a session would be new on each request.
   *
   * @return true if the server has created a session, but the client has not yet joined
   * @throws java.lang.IllegalStateException - if this method is called on an already invalidated session
   */
  @Override
  public boolean isNew()
  {
    return newSession;
  }

  void assertValid()
  {
    if (invalidated)
    {
      throw new IllegalStateException("This session has been invalidated.");
    }
  }
}
