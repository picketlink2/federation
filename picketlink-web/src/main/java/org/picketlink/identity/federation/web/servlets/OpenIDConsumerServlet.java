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
package org.picketlink.identity.federation.web.servlets;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.picketlink.identity.federation.api.openid.OpenIDManager;  
import org.picketlink.identity.federation.api.openid.OpenIDRequest;
import org.picketlink.identity.federation.api.openid.OpenIDManager.OpenIDProviderInformation;
import org.picketlink.identity.federation.api.openid.OpenIDManager.OpenIDProviderList;
import org.picketlink.identity.federation.api.openid.exceptions.OpenIDGeneralException; 
import org.picketlink.identity.federation.web.openid.HTTPOpenIDContext;
import org.picketlink.identity.federation.web.openid.HTTPProtocolAdaptor;

/**
 * OpenID Consumer Servlet that gets a post
 * request from the main JSP page of the consumer
 * web application.
 * @author Anil.Saldhana@redhat.com
 * @since Jul 10, 2009
 */
public class OpenIDConsumerServlet extends HttpServlet
{
   private static final long serialVersionUID = 1L; 
 
   private transient ServletContext servletContext;
   private String returnURL;

   @Override
   public void init(ServletConfig config) throws ServletException
   {
      super.init(config);
      this.servletContext = config.getServletContext(); 
      returnURL = this.servletContext.getInitParameter("returnURL"); 
   }
   
   @Override
   protected void doPost(HttpServletRequest req, HttpServletResponse resp) 
   throws ServletException, IOException
   {
      if(returnURL == null)
         returnURL = "http://" + req.getServerName() + ":" + req.getServerPort() +
                 req.getContextPath() + "/consumer_return.jsp";
      
      String userEntry = req.getParameter("openid");
      OpenIDRequest openIDReq = new OpenIDRequest(userEntry);
      
      HttpSession session = req.getSession();
      OpenIDManager manager = (OpenIDManager) session.getAttribute("openid_manager");
      if(manager == null)
      {
         manager = new OpenIDManager(openIDReq);
         session.setAttribute("openid_manager", manager); 
      }
      
      try
      {
         OpenIDProviderList listOfProviders = manager.discoverProviders();
         HTTPOpenIDContext httpOpenIDCtx = new HTTPOpenIDContext(req,resp, this.servletContext);
         httpOpenIDCtx.setReturnURL(returnURL);
         
         HTTPProtocolAdaptor adapter = new HTTPProtocolAdaptor(httpOpenIDCtx);
         OpenIDProviderInformation providerInfo = manager.associate(adapter, listOfProviders);
         manager.authenticate(adapter, providerInfo);
      }
      catch (OpenIDGeneralException e)
      {
         log("[OpenIDConsumerServlet]Exception in dealing with the provider:",e);
         resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
      } 
   }
}