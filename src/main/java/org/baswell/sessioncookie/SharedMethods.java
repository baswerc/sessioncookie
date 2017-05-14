package org.baswell.sessioncookie;

class SharedMethods
{
  static boolean hasContent(String value)
  {
    return value != null && !value.trim().isEmpty();
  }
}
