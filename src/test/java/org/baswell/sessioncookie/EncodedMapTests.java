package org.baswell.sessioncookie;

import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import static org.junit.Assert.*;

public class EncodedMapTests
{
  @Test
  public void test() throws Exception
  {
    EncodedMap expectedMap = new EncodedMap();
    expectedMap.put("One", 1);
    expectedMap.put("Two", "2");
    expectedMap.put("Three", false);
    expectedMap.put("Four", 3.45);

    String encodedValue = expectedMap.encode();
    EncodedMap actualMap = new EncodedMap(encodedValue);

    assertEquals(expectedMap, actualMap);
  }
}
