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
package org.jboss.test.identity.federation.web.openid;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Map;

import org.jboss.identity.federation.api.openid.OpenIDAttributeMap;
import org.jboss.identity.federation.api.openid.OpenIDLifecycle;
import org.jboss.identity.federation.api.openid.OpenIDLifecycleEvent;
import org.jboss.identity.federation.api.openid.OpenIDProtocolAdapter;
import org.jboss.identity.federation.api.openid.exceptions.OpenIDLifeCycleException;
import org.jboss.identity.federation.api.openid.exceptions.OpenIDProtocolException;

/**
 * Adapter that is in memory or the same VM
 * @author Anil.Saldhana@redhat.com
 * @since Jul 7, 2009
 */
public class InMemoryProtocolAdapter implements OpenIDProtocolAdapter, OpenIDLifecycle
{ 
   public OpenIDAttributeMap getAttributeMap()
   { 
      return new OpenIDAttributeMap();
   }
   
   public void handle(OpenIDLifecycleEvent event)
   { 
   }

   public Object getAttributeValue(String name)
   {
      return null;
   }

   public void handle(OpenIDLifecycleEvent[] eventArr) throws OpenIDLifeCycleException
   { 
   } 
   
   public String getReturnURL()
   {
      return "http://localhost:11080";
   }

   public void sendToProvider(int version, String destinationURL, Map<String, String> paramMap)
         throws OpenIDProtocolException
   {
      System.out.println("Version="+ version);
      System.out.println("destinationURL="+ destinationURL);
      System.out.println("paramMap="+ paramMap);
      
      if(version == 1)
      {
         URL url;
         try
         {
            url = new URL(destinationURL);
            URLConnection urlConn = url.openConnection();
            for (int i=0; ; i++) 
            {
               String headerName = urlConn.getHeaderFieldKey(i);
               String headerValue = urlConn.getHeaderField(i);
       
               if (headerName == null && headerValue == null) 
               {
                   // No more headers
                   break;
               }
               if (headerName == null) 
               {
                   // The header value contains the server's HTTP version
               }
           }

         }
         catch (MalformedURLException e)
         {
            throw new OpenIDProtocolException(e);
         }
         catch (IOException e)
         {
            throw new OpenIDProtocolException(e);
         }
          
      }
      else
      {
         throw new RuntimeException("Not implemented");
      }
   }
}