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
import java.io.InputStream;
import java.io.OutputStream;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet used for Yadis Discovery in OpenID
 * @author Anil.Saldhana@redhat.com
 * @since Jul 7, 2009
 */
public class OpenIDYadisServlet extends HttpServlet
{
   private static final long serialVersionUID = 1L; 
   
   private String yadisResourceFile = "/WEB-INF/openid-yadis.xml";
   private String yadisURL = null;
   
   private boolean supportHTTP_HEAD = false; //By default, we support GET
   
   private transient InputStream yadisResourceInputStream = null;
    
   @Override
   public void init(ServletConfig config) throws ServletException
   {
      super.init(config);
      ServletContext context = config.getServletContext();
      
      String yadisResourceFileStr = config.getInitParameter("yadisResourceFile");
      if(yadisResourceFileStr != null && yadisResourceFileStr.length() > 0)
         yadisResourceFile = yadisResourceFileStr;
      log("yadisResourceFile Location="+ yadisResourceFile);
       
      yadisURL = config.getInitParameter("yadisResourceURL");
      
      if(yadisURL == null || yadisURL.length() == 0)
      {
         yadisResourceInputStream = context.getResourceAsStream(yadisResourceFile);
         if(yadisResourceInputStream == null)
            throw new RuntimeException("yadisResourceFile is missing"); 
      }
    
      String supportHead = config.getInitParameter("support_HTTP_HEAD");
      if(supportHead != null && supportHead.length() > 0)
         supportHTTP_HEAD = Boolean.parseBoolean(supportHead);
   }
 

   @Override
   protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
   {
      if(this.supportHTTP_HEAD)
      {
         log("GET not supported as HTTP HEAD has been configured");
         resp.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
         return;
      }
      else
      { 
         if(yadisResourceInputStream == null)
         {
            log("ERROR::yadisResourceInputStream is null");
            resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return; 
         }
         
         byte[] barr = new byte[1024];
         for (int i = 0; i < barr.length; i++) 
         {
            int b = yadisResourceInputStream.read( );
            if (b  == -1) break;
            barr[i] = (byte) b;
          }
         
         resp.setContentType("application/xrds+xml");
         resp.setStatus(HttpServletResponse.SC_OK);  
         OutputStream os = resp.getOutputStream();
         os.write(barr);
         os.flush();
         os.close(); 
      } 
   }

   @Override
   protected void doHead(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
   {
       if(this.supportHTTP_HEAD)
       {
          resp.addHeader("X-XRDS-Location", yadisURL); 
       }
       resp.setStatus(HttpServletResponse.SC_OK);  
       return;
   } 
}