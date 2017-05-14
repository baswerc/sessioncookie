package org.baswell.sessioncookie;

import java.security.GeneralSecurityException;

/**
 * Thrown when a session cookie value could not be decrypted.
 */
public class SessionCookieDecryptionException extends Exception
{
  /**
   * The key used to to try and decrypt the session cookie.
   */
  public final byte[] key;

  /**
   * The algorithm used to try and decrypt the session cookie.
   */
  public final String algorithm;

  /**
   * The cookie value that could not be decrypted.
   */
  public final byte[] encryptedData;

  /**
   * The exception thrown attempting the decrypt.
   */
  public final GeneralSecurityException generalSecurityException;

  public SessionCookieDecryptionException(byte[] key, String algorithm, byte[] encryptedData, GeneralSecurityException generalSecurityException)
  {
    super(generalSecurityException);
    this.key = key;
    this.algorithm = algorithm;
    this.encryptedData = encryptedData;
    this.generalSecurityException  = generalSecurityException;
  }
}
