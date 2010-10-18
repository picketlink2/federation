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
package org.picketlink.test.identity.federation.core.parser.wst;

import static org.junit.Assert.assertEquals;

import java.io.InputStream;

import javax.xml.bind.JAXBElement;

import org.junit.Test;
import org.picketlink.identity.federation.core.parsers.wst.WSTrustParser;
import org.picketlink.identity.federation.core.wstrust.WSTrustConstants;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityToken;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;
import org.picketlink.identity.federation.ws.trust.RenewTargetType;

/**
 * Validate the parsing of wst-batch-validate.xml
 * @author Anil.Saldhana@redhat.com
 * @since Oct 12, 2010
 */
public class WSTrustRenewTargetParsingTestCase
{
   @Test 
   public void testWST_RenewTarget() throws Exception
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream configStream = tcl.getResourceAsStream( "parser/wst/wst-renew-saml.xml" );
      
      WSTrustParser parser = new WSTrustParser();
      RequestSecurityToken requestToken = (RequestSecurityToken) parser.parse( configStream );  
      assertEquals( "renewcontext", requestToken.getContext() );
      assertEquals( WSTrustConstants.RENEW_REQUEST , requestToken.getRequestType().toASCIIString() );
      assertEquals( WSTrustConstants.SAML2_TOKEN_TYPE , requestToken.getTokenType().toASCIIString() ); 
      
      RenewTargetType renewTarget = requestToken.getRenewTarget();
      AssertionType assertion = (AssertionType) renewTarget.getAny();
      assertEquals( "ID_654b6092-c725-40ea-8044-de453b59cb28", assertion.getID() );
      assertEquals( "Test STS", assertion.getIssuer().getValue() );
      SubjectType subject = assertion.getSubject();
      
      @SuppressWarnings("unchecked")
      JAXBElement<NameIDType> nameID = (JAXBElement<NameIDType>) subject.getContent().get(0);
      assertEquals( "jduke", nameID.getValue().getValue());
      
   } 
}