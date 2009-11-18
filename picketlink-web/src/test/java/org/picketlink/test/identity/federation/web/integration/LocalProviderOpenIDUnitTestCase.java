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
package org.picketlink.test.identity.federation.web.integration;

import java.io.IOException;
import java.io.InputStream;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.picketlink.identity.federation.api.openid.OpenIDManager;  
import org.picketlink.identity.federation.api.openid.OpenIDRequest; 
import org.picketlink.identity.federation.api.openid.OpenIDManager.OpenIDProviderInformation;
import org.picketlink.identity.federation.api.openid.OpenIDManager.OpenIDProviderList;
import org.picketlink.test.identity.federation.web.openid.InMemoryProtocolAdapter;
import org.picketlink.test.identity.federation.web.server.EmbeddedWebServerBase;
import org.mortbay.jetty.servlet.Context;
import org.mortbay.jetty.servlet.ServletHolder;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.DirectError;
import org.openid4java.message.Message;
import org.openid4java.message.ParameterList;
import org.openid4java.server.InMemoryServerAssociationStore;
import org.openid4java.server.ServerManager;

/**
 * Test the OpenID functionality within the VM
 * @author Anil.Saldhana@redhat.com
 * @since Jul 7, 2009
 */
public class LocalProviderOpenIDUnitTestCase extends EmbeddedWebServerBase
{  
   protected void establishUserApps()
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream is = tcl.getResourceAsStream("openid/localhost-yadis.xml");

      assertNotNull("Yadis descriptor not null", is);

      Context context = new Context(server,"/",Context.SESSIONS); 
      context.addServlet(new ServletHolder(new YadisServlet(is)), "/*");

      context.addServlet(new ServletHolder(new ProviderServlet()), "/provider/");
   }

   public void testOpenIDAuth() throws Exception
   {
      //String username = "http://jbosstest.myopenid.com";
      String username = "http://localhost:11080";
      InMemoryProtocolAdapter ad = new InMemoryProtocolAdapter();
      OpenIDRequest openIDRequest = new OpenIDRequest(username);
      OpenIDManager idm = new OpenIDManager(openIDRequest); 
      OpenIDProviderList providers = idm.discoverProviders();
      assertNotNull("List of providers is not null", providers);

      OpenIDProviderInformation providerInfo = idm.associate(ad,providers);
      idm.authenticate(ad, providerInfo);  
   }

   //A provider servlet that always returns true
   private static class ProviderServlet extends HttpServlet
   {
      private static final long serialVersionUID = 1L; 
      
      @Override
      protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
      {
         doGet(req, resp);
      }

      @Override
      protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
      {
         System.out.println("Inside ProviderServlet::doGet");
         
         ParameterList requestP = new ParameterList(req.getParameterMap());
         
         ServerManager manager = new ServerManager();
         manager.setSharedAssociations(new InMemoryServerAssociationStore());
         manager.setPrivateAssociations(new InMemoryServerAssociationStore());
         manager.setOPEndpointUrl("http://localhost:11080/provider/");
         
         String userSelectedId = "http://test.localhost:11080";
         String userSelectedClaimedId = userSelectedId;
         boolean authenticatedAndApproved = true;
         
         String responseText = "";
         
         String mode = requestP.hasParameter("openid.mode") ?
               requestP.getParameterValue("openid.mode") : null;

         System.out.println("ProviderServlet::mode="+mode);
         Message responsem ;
         if ("associate".equals(mode))
         {
                  // --- process an association request ---
                  responsem = manager.associationResponse(requestP);
                  responseText = responsem.keyValueFormEncoding().trim();
         }
         else if ("checkid_setup".equals(mode)
               || "checkid_immediate".equals(mode))
         {
            responsem = manager.authResponse(requestP,
                  userSelectedId,
                  userSelectedClaimedId,
                  authenticatedAndApproved );

            if (responsem instanceof AuthSuccess)
            {
                resp.sendRedirect(((AuthSuccess) responsem).getDestinationUrl(true));
                return;
            }
            else
            {
                responseText="<pre>"+responsem.keyValueFormEncoding().trim()+"</pre>";
            } 
         }
         else if ("check_authentication".equals(mode))
         {
             // --- processing a verification request ---
             responsem = manager.verify(requestP);
             responseText = responsem.keyValueFormEncoding().trim();
         }
         else
         {
             // --- error response ---
             responsem = DirectError.createDirectError("Unknown request");
             responseText = responsem.keyValueFormEncoding().trim();
         }

         resp.setStatus(HttpServletResponse.SC_OK); 
         resp.getWriter().print(responseText);
      }  
   }
   
   //A Yadis servlet that just reads the XML from the Inputstream and passes it back
   private class YadisServlet extends HttpServlet
   {
      private static final long serialVersionUID = 1L; 

      private InputStream yadisDescriptor;
    
      public YadisServlet(InputStream yadisDescriptor)
      {
         if(yadisDescriptor == null)
            throw new RuntimeException("input stream null");
         this.yadisDescriptor = yadisDescriptor; 
      } 

      protected void doGet(HttpServletRequest request, HttpServletResponse resp) 
      throws ServletException, IOException
      {
         System.out.println("Inside Yadis Servlet");
         if("HEAD".equals(request.getMethod()))
         {
            resp.setStatus(HttpServletResponse.SC_OK); 
            return; 
         }
         //Asking for Yadis discovery
         byte[] barr = new byte[1024];
         for (int i = 0; i < barr.length; i++) 
         {
            int b = yadisDescriptor.read();
            if (b  == -1) break;
            barr[i] = (byte) b;
          }
         resp.setContentType("application/xrds+xml");
         resp.setStatus(HttpServletResponse.SC_OK);  
         
         String ycontent = new String(barr);
         ycontent = ycontent.replace("\n"," ").trim();  
         resp.getWriter().print(ycontent); 
      }
   }
}