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
package org.jboss.test.identity.federation.web.integration;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.identity.federation.api.openid.OpenIDManager; 
import org.jboss.identity.federation.api.openid.OpenIDRequest; 
import org.jboss.identity.federation.api.openid.OpenIDManager.OpenIDProviderList;
import org.jboss.identity.federation.web.servlets.OpenIDYadisServlet;
import org.jboss.test.identity.federation.web.server.EmbeddedWebServerBase;
import org.mortbay.jetty.servlet.Context;
import org.mortbay.jetty.servlet.ServletHolder;

/**
 * Unit test the OpenID Yadis Servlet
 * @author Anil.Saldhana@redhat.com
 * @since Jul 7, 2009
 */
public class YadisMetadataUnitTestCase extends EmbeddedWebServerBase
{    
   protected void establishUserApps()
   {
      Context context = new Context(server,"/",Context.SESSIONS);
      ServletHolder servletHolder = new ServletHolder(new OpenIDYadisServlet()); 
      servletHolder.setInitParameter("support_HTTP_HEAD", "true");
      servletHolder.setInitParameter("yadisResourceURL", "http://localhost:11080/yadis");
      
      context.addServlet(servletHolder, "/*");
      
      context.addServlet(new ServletHolder( new TestYadisResourceServlet()), "/yadis");
   }
   
   public void testYadisDiscovery() throws Exception
   {
      //String username = "http://jbosstest.myopenid.com";
      String username = "http://localhost:11080"; 
      
      OpenIDRequest openIDRequest = new OpenIDRequest(username);
      OpenIDManager idm = new OpenIDManager(openIDRequest);
      
      OpenIDProviderList providers = idm.discoverProviders(); 
      assertNotNull("Providers list is not null", providers);
      assertEquals("1 provider", 1, providers.size());
   }
   
   /**
    * Servlet that just outputs an Yadis resource
    */
   private class TestYadisResourceServlet extends HttpServlet
   {
      private static final long serialVersionUID = 1L;
    
      String yadis = "<xrds:XRDS "+
                        " xmlns:xrds=\'xri://$xrds\' " +
                        " xmlns:openid=\'http://openid.net/xmlns/1.0\'" +
                        " xmlns=\'xri://$xrd*($v*2.0)\'>" +
                        "<XRD>" +
                        " <Service priority=\'0\'>" +
                        " <Type>http://openid.net/signon/1.0</Type>" +
                        " <URI>http://localhost/provider.jsp</URI>" +
                        " </Service>"+
                        "</XRD>" +
                     "</xrds:XRDS>";
      @Override
      protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
      {
         resp.setContentType("application/xrds+xml");
         resp.setStatus(HttpServletResponse.SC_OK);
         resp.getWriter().print(yadis); 
      } 
   }
}