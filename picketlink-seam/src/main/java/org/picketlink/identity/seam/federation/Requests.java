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

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.AutoCreate;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.log.Log;
import org.picketlink.identity.seam.federation.configuration.SamlIdentityProvider;

/**
 * Session scoped component that stores requests that have been sent to the identity provider.
 * 
 * @author Marcel Kolsteren
 */
@Name("org.picketlink.identity.seam.federation.requests")
@AutoCreate
@Scope(ScopeType.SESSION)
public class Requests
{
   private Map<String, RequestContext> requests = new HashMap<String, RequestContext>();

   @Logger
   private Log log;

   public void addRequest(String id, SamlIdentityProvider identityProvider, String urlToRedirectToAfterLogin)
   {
      requests.put(id, new RequestContext(id, identityProvider, urlToRedirectToAfterLogin));
   }

   public RequestContext getRequest(String id)
   {
      return requests.get(id);
   }

   public void removeRequest(String id)
   {
      requests.remove(id);
   }

   public void redirect(String id, HttpServletResponse response)
   {
      String requestURL = requests.get(id).getUrlToRedirectToAfterLogin();
      if (requestURL == null)
      {
         throw new RuntimeException("Couldn't find URL to redirect to for request " + id);
      }
      try
      {
         if (log.isDebugEnabled())
         {
            log.debug("Redirecting to " + requestURL);
         }
         response.sendRedirect(requestURL);
      }
      catch (IOException e)
      {
         throw new RuntimeException(e);
      }
   }
}
