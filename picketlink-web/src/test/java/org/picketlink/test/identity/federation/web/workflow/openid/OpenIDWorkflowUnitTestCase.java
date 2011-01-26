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

import java.net.URL;

import org.mortbay.jetty.servlet.Context;
import org.mortbay.jetty.servlet.ServletHolder;
import org.mortbay.jetty.webapp.WebAppContext;
import org.picketlink.identity.federation.api.openid.OpenIDManager;
import org.picketlink.identity.federation.api.openid.OpenIDManager.OpenIDProviderInformation;
import org.picketlink.identity.federation.api.openid.OpenIDManager.OpenIDProviderList;
import org.picketlink.identity.federation.api.openid.OpenIDRequest;
import org.picketlink.identity.federation.web.servlets.OpenIDProviderServlet;
import org.picketlink.test.identity.federation.web.openid.InMemoryProtocolAdapter;
import org.picketlink.test.identity.federation.web.server.EmbeddedWebServerBase;


/**
 * Test the workflow of an OpenID Consumer with a provider
 * @author Anil.Saldhana@redhat.com
 * @since Jan 18, 2011
 */
public class OpenIDWorkflowUnitTestCase extends EmbeddedWebServerBase
{ 
   private String username = "http://localhost:11080";
   private OpenIDRequest openIDRequest = new OpenIDRequest( username ); 
   private OpenIDManager manager = new OpenIDManager( openIDRequest ); 
   
   protected void establishUserApps()
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      
      final String WEBAPPDIR = "openid/webapp"; 

      final String CONTEXTPATH = "/";

      // for localhost:port/admin/index.html and whatever else is in the webapp directory
      final URL warUrl = tcl.getResource(WEBAPPDIR);
      final String warUrlString = warUrl.toExternalForm();
      
      Context context = new WebAppContext( warUrlString, CONTEXTPATH );
      server.setHandler( context );
 
      context.addServlet(new ServletHolder(new OpenIDProviderServlet()), "/provider/");
      
      context.addServlet( new ServletHolder( new OpenIDWorkflowTestConsumerServlet( manager)), "/consumer" );
      
      context.addFilter(PrincipalInducingTestServletFilter.class, "/securepage.jsp",  1 );
   }

   public void testOpenIDAuth() throws Exception
   {   
      InMemoryProtocolAdapter ad = new InMemoryProtocolAdapter(); 
      OpenIDProviderList providers = manager.discoverProviders();
      assertNotNull("List of providers is not null", providers);

      OpenIDProviderInformation providerInfo = manager.associate( ad,providers );
      boolean isValid = manager.authenticate( ad, providerInfo );
      assertTrue( "Authentication is valid" , isValid );
   } 
}