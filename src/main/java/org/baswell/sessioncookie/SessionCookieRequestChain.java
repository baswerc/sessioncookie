package org.baswell.sessioncookie;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Used to forward an HTTP request down the request pipeline.
 *
 *
 */
public interface SessionCookieRequestChain
{
  void forward(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException;
}
