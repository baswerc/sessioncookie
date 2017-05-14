package org.baswell.sessioncookie;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;
import java.util.HashMap;

class EncodedMap extends HashMap<String, Object>
{
  EncodedMap()
  {}

  EncodedMap(String encodedData) throws ClassNotFoundException
  {
    try
    {
      ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(encodedData)));
      HashMap<String, Object> map = (HashMap<String, Object>) ois.readObject();
      ois.close();

      putAll(map);
    }
    catch (IOException e)
    {
      throw new RuntimeException(e);
    }

  }

  public String encode()
  {
    try
    {
      ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
      ObjectOutputStream oos = new ObjectOutputStream(bytesOut);
      oos.writeObject(this);
      oos.close();
      return Base64.getEncoder().encodeToString(bytesOut.toByteArray());
    }
    catch (IOException e)
    {
      throw new RuntimeException(e);
    }
  }
}
