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
package org.picketlink.test.identity.federation.web.openid;

import java.net.URL;
import java.util.Map;

import org.picketlink.identity.federation.api.openid.OpenIDAttributeMap;
import org.picketlink.identity.federation.api.openid.OpenIDLifecycle;
import org.picketlink.identity.federation.api.openid.OpenIDLifecycleEvent;
import org.picketlink.identity.federation.api.openid.OpenIDProtocolAdapter;
import org.picketlink.identity.federation.api.openid.exceptions.OpenIDLifeCycleException;
import org.picketlink.identity.federation.api.openid.exceptions.OpenIDProtocolException;

import com.meterware.httpunit.GetMethodWebRequest;
import com.meterware.httpunit.WebConversation;
import com.meterware.httpunit.WebForm;
import com.meterware.httpunit.WebRequest;
import com.meterware.httpunit.WebResponse;

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
      return "http://localhost:11080/consumer";
   }

   public void sendToProvider(int version, String destinationURL, Map<String, String> paramMap)
         throws OpenIDProtocolException
   {
      System.out.println("Version="+ version);
      System.out.println("destinationURL="+ destinationURL);
      System.out.println("paramMap="+ paramMap);
      
      if(version == 1)
      {   
         WebConversation wc = new WebConversation();
         wc.setAuthorization( "anil", "anil" );
         WebRequest req = new GetMethodWebRequest( destinationURL );
         try
         {
            WebResponse resp = wc.getResponse( req );
            URL responseURL = resp.getURL(); 
            if( responseURL.toString().contains( "securepage.jsp" ))
            {
               resp = wc.getResponse( responseURL.toString() );
               WebForm form = resp.getForms()[0];
               resp = form.submit();
            }
         }
         catch ( Exception e)
         { 
            e.printStackTrace();
            throw new OpenIDProtocolException();
         }  
      }
      else
      {
         throw new RuntimeException("Not implemented");
      }
   }
}