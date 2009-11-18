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
package org.jboss.test.identity.federation.core.saml.v2;

import org.jboss.identity.federation.saml.v2.SAML2Object;
import org.jboss.identity.federation.saml.v2.protocol.AuthnRequestType;
import org.jboss.identity.federation.saml.v2.protocol.LogoutRequestType;
import org.jboss.identity.federation.saml.v2.protocol.ObjectFactory;
import org.jboss.identity.federation.saml.v2.protocol.StatusResponseType;

import junit.framework.TestCase;

/**
 * Unit test the SAML2Object interface
 * @author Anil.Saldhana@redhat.com
 * @since Sep 17, 2009
 */
public class SAML2ObjectUnitTestCase extends TestCase
{
   public void testSAML2Object()
   {
      ObjectFactory factory = new ObjectFactory();
      
      //Request Types
      LogoutRequestType lo = factory.createLogoutRequestType();
      assertTrue("LogOutRequest is SAML2Object?", lo instanceof SAML2Object);
      
      AuthnRequestType ar = factory.createAuthnRequestType();
      assertTrue("AuthnRequest is SAML2Object?", ar instanceof SAML2Object);
      
      //Response Types
      StatusResponseType status = factory.createStatusResponseType();
      assertTrue("StatusResponseType is SAML2Object?", status instanceof SAML2Object);
   }
}