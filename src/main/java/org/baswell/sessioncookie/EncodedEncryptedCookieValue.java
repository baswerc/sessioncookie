package org.baswell.sessioncookie;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.UnknownFormatConversionException;

import static java.lang.String.format;

class EncodedEncryptedCookieValue
{
  static EncodedEncryptedCookieValue decodeAndDecrypt(String encodedEncryptedValue, byte[] key, String algorithm) throws GeneralSecurityException, SessionCookieDecryptionException, SessionCookieDecodingException
  {
    Cipher cipher = Cipher.getInstance(algorithm);
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, algorithm));

    try
    {
      String data = new String(cipher.doFinal(Base64.getDecoder().decode(encodedEncryptedValue)));
      String[] split = data.split(DELIMITER);

      if (split.length != 2)
      {
        throw new SessionCookieDecodingException(format("Invalid number of sections %i in cookie value %s.", split.length, data), data);
      }
      else
      {
        return new EncodedEncryptedCookieValue(split[0], split[1]);
      }
    }
    catch (UnknownFormatConversionException e)
    {
      throw new SessionCookieDecodingException(format("Invalid Base64 encoded cookie value."), encodedEncryptedValue, e);
    }
    catch (GeneralSecurityException e)
    {
      throw new SessionCookieDecryptionException(key, algorithm, encodedEncryptedValue.getBytes(), e);
    }
  }

  static String encodeAndEncrypt(String controlData, String sessionData, byte[] key, String algorithm) throws GeneralSecurityException
  {
    Cipher cipher = Cipher.getInstance(algorithm);
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, algorithm));
    byte[] data = (controlData + DELIMITER + sessionData).getBytes();
    return Base64.getEncoder().encodeToString(cipher.doFinal(data));
  }

  final String controlData;

  final String sessionData;

  public EncodedEncryptedCookieValue(String controlData, String sessionData)
  {
    this.controlData = controlData;
    this.sessionData = sessionData;
  }

  static final String DELIMITER = ",";
}
