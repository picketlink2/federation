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
package org.jboss.identity.federation.core.factories;

import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.jboss.identity.federation.core.util.JAXBUtil;
import org.jboss.identity.federation.org.xmlsoap.schemas.soap.envelope.ObjectFactory;

/**
 * Provides an handle to the ObjectFactory that is capable
 * of creating SOAP objects
 * @author Anil.Saldhana@redhat.com
 * @since Jan 28, 2009
 */
public class SOAPFactory
{
   private static ObjectFactory factory = new ObjectFactory();
   
   public static ObjectFactory getObjectFactory()
   {
      return factory;
   }
   
   public static Marshaller getMarshaller() throws JAXBException
   {
      return JAXBUtil.getMarshaller("org.jboss.identity.federation.org.xmlsoap.schemas.soap.envelope"); 
   }
   
   public static Unmarshaller getUnmarshaller() throws JAXBException
   {
      return JAXBUtil.getUnmarshaller("org.jboss.identity.federation.org.xmlsoap.schemas.soap.envelope"); 
   }
}