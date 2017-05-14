package org.baswell.sessioncookie;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpSession;

import java.security.GeneralSecurityException;

import static java.lang.String.format;

/**
 * Default error handler that logs all events using the SL4J logging library.
 */
public class SessionCookieDefaultErrorHandler implements SessionCookieErrorHandler
{
  protected final Logger log = LoggerFactory.getLogger(getClass());

  public void onSessionCookieSizeWarning(HttpSession session, int cookieSizeBytes)
  {
    log.warn(format("The session cookie for %s is %i bytes in size and might not be re=transmitted by the browser could not be decoded.", session.getId(), cookieSizeBytes));
  }

  public void onCookieDecodeError(SessionCookieDecodingException exception)
  {
    log.warn(format("Received session cookie \"%s\" that could not be decoded.", exception.decryptedCookieValue), exception);
  }

  public void onCookieDecryptError(SessionCookieDecryptionException exception)
  {
    log.warn(format("Received session cookie \"%s\" that could not be decrypted using algorithm %s.", exception.encryptedData, exception.algorithm), exception);
  }

  public void onGeneralSecurityException(GeneralSecurityException exception, SessionCookieParameters parameters, boolean encrypting)
  {
    log.error(format("Received a general security exception using the SessionCookie parameters %s and cipher algorithm %s while %s.",
        parameters.getClass().toString(), parameters.getSymmetricEncryptionAlgorithm(), (encrypting ? "encrypting" : "decrypting")), exception);
  }

  public void onClassNotFoundFromSessionException(ClassNotFoundException exception)
  {
    log.error("Class not found exception from within session.", exception);
  }
}
