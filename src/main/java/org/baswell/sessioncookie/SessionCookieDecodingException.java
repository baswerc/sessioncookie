package org.baswell.sessioncookie;

/**
 * Thrown when a session cookie value is decrypted but not able to be decoded.
 */
public class SessionCookieDecodingException extends Exception
{
  /**
   * The decrypted cookie value that could not be decoded.
   */
  public final String decryptedCookieValue;

  public SessionCookieDecodingException(String message, String decryptedCookieValue)
  {
    super(message);
    this.decryptedCookieValue = decryptedCookieValue;
  }

  public SessionCookieDecodingException(String message, String decryptedCookieValue, Throwable cause)
  {
    super(message, cause);
    this.decryptedCookieValue = decryptedCookieValue;
  }

}
