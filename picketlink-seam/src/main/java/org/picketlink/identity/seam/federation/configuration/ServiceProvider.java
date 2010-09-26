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
package org.picketlink.identity.seam.federation.configuration;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.Principal;
import java.util.List;

import org.jboss.seam.core.Expressions;
import org.jboss.seam.core.Expressions.MethodExpression;
import org.picketlink.identity.seam.federation.ExternalAuthenticationService;
import org.picketlink.identity.seam.federation.jaxb.config.ServiceProviderType;

/**
* @author Marcel Kolsteren
* @since Jan 17, 2010
*/
public class ServiceProvider
{
   private Configuration configuration;

   private SamlConfiguration samlConfiguration;

   private OpenIdConfiguration openIdConfiguration;

   private FacebookConfiguration facebookConfiguration;

   private String hostname;

   private String protocol;

   private int port;

   private String loggedOutUrl;

   private String unsolicitedAuthenticationUrl;

   private String failedAuthenticationUrl;

   private MethodExpression<Boolean> internalAuthenticationMethod;

   public ServiceProvider(Configuration configuration, ServiceProviderType serviceProvider)
   {
      this.configuration = configuration;

      hostname = serviceProvider.getHostname();
      protocol = serviceProvider.getProtocol().value();

      loggedOutUrl = serviceProvider.getLoggedOutUrl();
      unsolicitedAuthenticationUrl = serviceProvider.getUnsolicitedAuthenticationUrl();
      failedAuthenticationUrl = serviceProvider.getFailedAuthenticationUrl();

      internalAuthenticationMethod = Expressions.instance().createMethodExpression(
            serviceProvider.getInternalAuthenticationMethod(), Boolean.class, Principal.class, List.class);

      if (serviceProvider.getPort() == null)
      {
         if (protocol.equals("http"))
         {
            port = 8080;
         }
         else
         {
            port = 8443;
         }
      }
      else
      {
         port = serviceProvider.getPort().intValue();
      }

      if (serviceProvider.getSamlConfig() != null)
      {
         samlConfiguration = new SamlConfiguration(serviceProvider.getSamlConfig());
      }

      if (serviceProvider.getOpenIdConfig() != null)
      {
         openIdConfiguration = new OpenIdConfiguration(serviceProvider.getOpenIdConfig());
      }

      if (serviceProvider.getFacebookConfig() != null)
      {
         facebookConfiguration = new FacebookConfiguration(serviceProvider.getFacebookConfig());
      }
   }

   public String getServiceURL(ExternalAuthenticationService service)
   {
      String path = configuration.getContextRoot() + "/" + service.getName() + ".seam";
      return createURL(path);
   }

   public String getOpenIdRealm()
   {
      return createURL("");
   }

   private String createURL(String path)
   {
      try
      {
         if (protocol.equals("http") && port == 80 || protocol.equals("https") && port == 443)
         {
            return new URL(protocol, hostname, path).toExternalForm();
         }
         else
         {
            return new URL(protocol, hostname, port, path).toExternalForm();
         }
      }
      catch (MalformedURLException e)
      {
         throw new RuntimeException(e);
      }
   }

   public SamlConfiguration getSamlConfiguration()
   {
      return samlConfiguration;
   }

   public OpenIdConfiguration getOpenIdConfiguration()
   {
      return openIdConfiguration;
   }

   public FacebookConfiguration getFacebookConfiguration()
   {
      return facebookConfiguration;
   }

   public String getHostname()
   {
      return hostname;
   }

   public String getProtocol()
   {
      return protocol;
   }

   public int getPort()
   {
      return port;
   }

   public String getLoggedOutUrl()
   {
      return loggedOutUrl;
   }

   public String getUnsolicitedAuthenticationUrl()
   {
      return unsolicitedAuthenticationUrl;
   }

   public String getFailedAuthenticationUrl()
   {
      return failedAuthenticationUrl;
   }

   public MethodExpression<Boolean> getInternalAuthenticationMethod()
   {
      return internalAuthenticationMethod;
   }
}
