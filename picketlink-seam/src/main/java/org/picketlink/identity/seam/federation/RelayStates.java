/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2008, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors. 
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.picketlink.identity.seam.federation;

import static org.jboss.seam.ScopeType.SESSION;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.Startup;

/**
 * Session scoped component that stores relay states. Each relay state corresponds to an uncompleted authorization request 
 * that has been sent to the IDP. The state is used to store the URL of the page that has been requested by the user.
 * Each state has an integer number that can be used as the RelayState parameter in the SAMLv2 authentication protocol.
 * 
 * @author Marcel Kolsteren
 */
@Scope(SESSION)
@Name("org.picketlink.identity.seam.federation.relayStates")
@Startup
public class RelayStates
{
   private Map<Integer, String> states = new HashMap<Integer, String>();

   private int nextIndex = 0;

   public int saveState(HttpServletRequest request)
   {
      int index = nextIndex++;

      StringBuffer requestURL = request.getRequestURL();
      if (request.getQueryString() != null)
      {
         requestURL.append("?" + request.getQueryString());
      }

      states.put(index, requestURL.toString());
      return index;
   }

   public void restoreState(int index, HttpServletResponse response)
   {
      String requestURL = states.get(index);
      try
      {
         response.sendRedirect(requestURL);
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
      states.remove(index);
   }
}
