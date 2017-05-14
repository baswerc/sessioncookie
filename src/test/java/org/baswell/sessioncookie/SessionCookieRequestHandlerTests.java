package org.baswell.sessioncookie;

import org.junit.Test;

import java.util.Arrays;
import java.util.regex.Pattern;

import static org.baswell.sessioncookie.SessionCookieFilter.wrapRequest;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SessionCookieRequestHandlerTests
{
  @Test
  public void testWrapRequest()
  {
    assertTrue(wrapRequest("/test", "/test/abc", null, null));
    assertFalse(wrapRequest("/test", "/test/abc", null, Arrays.asList(Pattern.compile("/.*"))));
    assertFalse(wrapRequest("/test", "/test/abc", null, Arrays.asList(Pattern.compile("/abc.*"))));
    assertTrue(wrapRequest("/test", "/test/abc", null, Arrays.asList(Pattern.compile("/test/assets.*"))));
  }
}
