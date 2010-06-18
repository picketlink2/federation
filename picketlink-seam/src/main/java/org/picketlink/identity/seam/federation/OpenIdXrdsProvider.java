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
package org.picketlink.identity.seam.federation;

import java.io.OutputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.jboss.seam.annotations.AutoCreate;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.openid4java.discovery.DiscoveryInformation;
import org.picketlink.identity.seam.federation.configuration.ServiceProvider;
import org.picketlink.identity.seam.federation.jaxb.xrds.ObjectFactory;
import org.picketlink.identity.seam.federation.jaxb.xrds.Service;
import org.picketlink.identity.seam.federation.jaxb.xrds.Type;
import org.picketlink.identity.seam.federation.jaxb.xrds.URIPriorityAppendPattern;
import org.picketlink.identity.seam.federation.jaxb.xrds.XRD;
import org.picketlink.identity.seam.federation.jaxb.xrds.XRDS;

/**
* @author Marcel Kolsteren
* @since Jan 20, 2010
*/
@Name("org.picketlink.identity.seam.federation.openIdXrdsProvider")
@AutoCreate
public class OpenIdXrdsProvider
{
   @In
   private ServiceProvider serviceProvider;

   public void writeMetaData(OutputStream stream)
   {
      try
      {
         ObjectFactory objectFactory = new ObjectFactory();

         XRDS xrds = objectFactory.createXRDS();

         XRD xrd = objectFactory.createXRD();

         Type type = objectFactory.createType();
         type.setValue(DiscoveryInformation.OPENID2_RP);
         URIPriorityAppendPattern uri = objectFactory.createURIPriorityAppendPattern();
         uri.setValue(serviceProvider.getServiceURL(ExternalAuthenticationService.OPEN_ID_SERVICE));

         Service service = objectFactory.createService();
         service.getType().add(type);
         service.getURI().add(uri);

         xrd.getService().add(service);

         xrds.getOtherelement().add(xrd);

         JAXBContext jaxbContext = JAXBContext.newInstance("org.picketlink.identity.seam.federation.jaxb.xrds");
         Marshaller marshaller = jaxbContext.createMarshaller();
         marshaller.setProperty(Marshaller.JAXB_ENCODING, "UTF-8");
         marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
         marshaller.marshal(xrds, stream);
      }
      catch (JAXBException e)
      {
         throw new RuntimeException(e);
      }
   }
}
