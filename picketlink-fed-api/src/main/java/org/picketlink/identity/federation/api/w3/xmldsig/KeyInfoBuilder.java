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
package org.picketlink.identity.federation.api.w3.xmldsig;

import org.picketlink.identity.xmlsec.w3.xmldsig.KeyInfoType;
import org.picketlink.identity.xmlsec.w3.xmldsig.ObjectFactory;
 

/**
 * Builder for the W3C xml-dsig KeyInfoType
 * @author Anil.Saldhana@redhat.com
 * @since Apr 20, 2009
 */
public class KeyInfoBuilder
{
   private static ObjectFactory oFact = new ObjectFactory();
   
   /**
    * Create a KeyInfoType
    * @return
    */
   public static KeyInfoType createKeyInfo(String id)
   {
      KeyInfoType keyInfo = oFact.createKeyInfoType();
    
      keyInfo.setId(id);
      return keyInfo;
   }
   
   /**
    * Return the object factory. Useful in method chaining
    * @return
    */
   public static ObjectFactory getObjectFactory()
   {
      return oFact;
   }
}