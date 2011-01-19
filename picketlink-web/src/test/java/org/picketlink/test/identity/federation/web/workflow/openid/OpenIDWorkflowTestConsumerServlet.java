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
package org.picketlink.test.identity.federation.web.workflow.openid;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.picketlink.identity.federation.api.openid.OpenIDManager;
import org.picketlink.identity.federation.web.openid.HTTPOpenIDContext;
import org.picketlink.identity.federation.web.openid.HTTPProtocolAdaptor;

/**
 * Test Consumer Servlet
 * @author Anil.Saldhana@redhat.com
 * @since Jan 19, 2011
 */
public class OpenIDWorkflowTestConsumerServlet extends HttpServlet
{ 
   private static final long serialVersionUID = 1L;
   
   private OpenIDManager manager = null;
   
   public OpenIDWorkflowTestConsumerServlet( OpenIDManager mgr )
   {
      this.manager = mgr;
   }

   @SuppressWarnings("unchecked")
   @Override
   protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
   { 
      log( "Provider response:" + request.getQueryString() );
      log( "UserID Chosen=" + request.getParameter( "openid.identity" )); 
      
      // extract the receiving URL from the HTTP request
      StringBuffer receivingURL = request.getRequestURL();
      String queryString = request.getQueryString();
      if (queryString != null && queryString.length() > 0)
          receivingURL.append("?").append(request.getQueryString());

      HTTPProtocolAdaptor adapter = new HTTPProtocolAdaptor(new HTTPOpenIDContext( request,response, getServletContext() ));
      try
      { 
         boolean auth = manager.verify(adapter, request.getParameterMap(), receivingURL.toString() );
         if( !auth )
            throw new ServletException( "OpenID information from provider not successfully verified" );
      }
      catch ( Exception e)
      { 
         e.printStackTrace();
         throw new IOException();
      } 
   } 
}