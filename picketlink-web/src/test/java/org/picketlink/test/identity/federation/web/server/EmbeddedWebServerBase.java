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
package org.picketlink.test.identity.federation.web.server;

import junit.framework.TestCase;

import org.mortbay.jetty.Connector;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.bio.SocketConnector;

/**
 * Base class for embedded web server based tests
 * @author Anil.Saldhana@redhat.com
 * @since Jul 8, 2009
 */
public abstract class EmbeddedWebServerBase extends TestCase
{
   protected Server server = null;
   
   public void setUp() throws Exception
   {
      super.setUp(); 
      
      //Start the Jetty embedded container
      server = new Server();
      
      server.setConnectors(getConnectors());
      
      this.establishUserApps(); 

      server.start();        
   } 
   
   public void tearDown() throws Exception
   {
      if(server != null)
      {
         server.stop();
         server.destroy();
         server = null;
      } 
      super.tearDown();
   }
   
   /**
    * Return the connectors that need to be configured
    * on the server. Subclasses can create as many connectors
    * as they want
    * @return
    */
   protected Connector[] getConnectors()
   {
      Connector connector=new SocketConnector();
      connector.setPort(11080);
      return new Connector[]{connector}; 
   }
   
   /**
    * Establish the user applications - context, servlets etc
    */
   protected abstract void establishUserApps(); 
}