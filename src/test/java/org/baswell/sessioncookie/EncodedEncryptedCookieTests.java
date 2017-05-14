package org.baswell.sessioncookie;

import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.util.Base64;
import java.util.UUID;

import static org.junit.Assert.assertEquals;

public class EncodedEncryptedCookieTests
{
  @Test
  public void test() throws Exception
  {
    KeyGenerator generator = KeyGenerator.getInstance("AES");
    generator.init(256);
    SecretKey key = generator.generateKey();

    String sessionId = "#1";
    long createdAt = System.currentTimeMillis();
    long lastAccessedAt = 123456789;

    System.out.println(Base64.getEncoder().encodeToString(key.getEncoded()));

    EncodedMap expectedControlMap = new EncodedMap();
    expectedControlMap.put("createdAt", System.currentTimeMillis());
    expectedControlMap.put("lastAccessedAt", System.currentTimeMillis() + 234565);
    expectedControlMap.put("sessionId", UUID.randomUUID().toString());

    EncodedMap expectedSessionMap = new EncodedMap();
    expectedSessionMap.put("One", 1);
    expectedSessionMap.put("Two", "2");
    expectedSessionMap.put("Three", false);
    expectedSessionMap.put("Four", 3.45);

    String encodeAndEncrypt = EncodedEncryptedCookieValue.encodeAndEncrypt(expectedControlMap.encode(), expectedSessionMap.encode(), key.getEncoded(), "AES");
    EncodedEncryptedCookieValue actualCookie = EncodedEncryptedCookieValue.decodeAndDecrypt(encodeAndEncrypt, key.getEncoded(), "AES");

    EncodedMap actualControlMap = new EncodedMap(actualCookie.controlData);
    assertEquals(actualControlMap, expectedControlMap);

    EncodedMap actualSessionMap = new EncodedMap(actualCookie.sessionData);
    assertEquals(expectedSessionMap, actualSessionMap);
  }
}
