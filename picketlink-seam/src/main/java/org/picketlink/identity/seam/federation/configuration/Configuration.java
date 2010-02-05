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

import java.net.URL;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.jboss.seam.Component;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.AutoCreate;
import org.jboss.seam.annotations.Create;
import org.jboss.seam.annotations.Factory;
import org.jboss.seam.annotations.Import;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.Startup;
import org.jboss.seam.web.ServletContexts;
import org.picketlink.identity.seam.federation.config.jaxb.ExternalAuthenticationConfigType;
import org.picketlink.identity.seam.federation.config.jaxb.ServiceProviderType;
import org.xml.sax.SAXException;

/**
* @author Marcel Kolsteren
* @since Jan 17, 2010
*/
@Name("org.picketlink.identity.seam.federation.configuration")
@Scope(ScopeType.APPLICATION)
@AutoCreate
@Startup
@Import("org.picketlink.identity.seam.federation")
public class Configuration
{
   private final static String CONFIGURATION_FILE = "/external-authentication-config.xml";

   private String contextRoot;

   private Map<String, ServiceProvider> serviceProviderMap = new HashMap<String, ServiceProvider>();

   @Create
   public void init()
   {
      List<ServiceProvider> serviceProviders = new LinkedList<ServiceProvider>();
      ExternalAuthenticationConfigType externalAuthenticationConfig = readConfigurationFile();
      for (ServiceProviderType serviceProvider : externalAuthenticationConfig.getServiceProvider())
      {
         serviceProviders.add(new ServiceProvider(this, serviceProvider));
      }

      for (ServiceProvider sp : serviceProviders)
      {
         if (serviceProviderMap.containsKey(sp.getHostname()))
         {
            throw new RuntimeException("Two service providers have the same hostname");
         }
         serviceProviderMap.put(sp.getHostname(), sp);
      }
   }

   private ExternalAuthenticationConfigType readConfigurationFile()
   {
      ExternalAuthenticationConfigType externalAuthenticationConfig;
      try
      {
         JAXBContext jaxbContext = JAXBContext.newInstance("org.picketlink.identity.seam.federation.config.jaxb");
         Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
         URL schemaURL = getClass().getResource("/schema/config/external-authentication-config.xsd");
         Schema schema;
         try
         {
            schema = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI).newSchema(schemaURL);
         }
         catch (SAXException e)
         {
            throw new RuntimeException(e);
         }
         unmarshaller.setSchema(schema);

         JAXBElement<?> o = (JAXBElement<?>) unmarshaller.unmarshal(getClass().getResource(CONFIGURATION_FILE));
         externalAuthenticationConfig = (ExternalAuthenticationConfigType) o.getValue();
      }
      catch (JAXBException e)
      {
         throw new RuntimeException(e);
      }
      return externalAuthenticationConfig;
   }

   public static Configuration instance()
   {
      return (Configuration) Component.getInstance(Configuration.class);
   }

   public void setContextRoot(String contextRoot)
   {
      this.contextRoot = contextRoot;
   }

   public String getContextRoot()
   {
      return contextRoot;
   }

   @Factory(scope = ScopeType.EVENT, autoCreate = true, value = "org.picketlink.identity.seam.federation.serviceProvider")
   public ServiceProvider getServiceProvider()
   {
      String hostname = ServletContexts.instance().getRequest().getServerName();;
      return serviceProviderMap.get(hostname);
   }

   public ServiceProvider getServiceProvider(String hostname)
   {
      return serviceProviderMap.get(hostname);
   }
}
