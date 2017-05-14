package org.baswell.sessioncookie;

import javax.servlet.http.HttpSession;
import java.security.GeneralSecurityException;

/**
 * Interface for handling all errors and warnings from the SessionCookie library.
 */
public interface SessionCookieErrorHandler
{
  /**
   * Called when a session cookie value is equal to or greater than {@link SessionCookieParameters#getCookieSizeWarning()}. Most browsers only support a cookie size less then 4KB so
   * it's important to keep session cookies below this value.
   * @param session The HTTP session
   * @param cookieSizeBytes The size in bytes of the session cookie
   */
  void onSessionCookieSizeWarning(HttpSession session, int cookieSizeBytes);

  /**
   * Called when a received session cookie was decrypted but could not be decoded.
   * @param exception The exception thrown attempting to decode a cookie value.
   */
  void onCookieDecodeError(SessionCookieDecodingException exception);

  /**
   * Called when a received session cookie could not be decrypted.
   * @param exception The exception thrown attempting to decrypt a cookie value.
   */
  void onCookieDecryptError(SessionCookieDecryptionException exception);

  /**
   * Called when the {@link javax.crypto.Cipher} could not be initialized for the given {@link SessionCookieParameters#getSymmetricEncryptionAlgorithm()} and {@link SessionCookieParameters#getSymmetricEncryptionKey()}.
   * @param exception The exception thrown while initializing the {@link javax.crypto.Cipher}
   * @param parameters The session parameters used to initialize the {@link javax.crypto.Cipher}
   * @param encrypting true if this error occurred while trying to encrypt false if the error occurred while trying to decrypt.
   */
  void onGeneralSecurityException(GeneralSecurityException exception, SessionCookieParameters parameters, boolean encrypting);

  /**
   * Called when a {@link ClassNotFoundException} trying to deserialize a session from a cookie value.
   * @param exception The exception thrown while trying to deserialize the session
   */
  void onClassNotFoundFromSessionException(ClassNotFoundException exception);
}
