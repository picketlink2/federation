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

import org.junit.Test;
import org.picketlink.identity.federation.core.parsers.wst.WSTrustParser;
import org.picketlink.identity.federation.core.wstrust.WSTrustConstants;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityToken;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.ws.trust.ValidateTargetType;

/**
 * Validate the parsing of wst-validate-saml.xml
 * @author Anil.Saldhana@redhat.com
 * @since Oct 12, 2010
 */
public class WSTrustValidateSamlTestCase
{
   @Test 
   public void testWST_ValidateSaml() throws Exception
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream configStream = tcl.getResourceAsStream( "parser/wst/wst-validate-saml.xml" );
      
      WSTrustParser parser = new WSTrustParser();
      RequestSecurityToken rst1 = (RequestSecurityToken) parser.parse( configStream );  
      assertEquals( "validatecontext", rst1.getContext() );
      assertEquals( WSTrustConstants.VALIDATE_REQUEST, rst1.getRequestType().toASCIIString() );
      assertEquals( WSTrustConstants.RSTR_STATUS_TOKEN_TYPE, rst1.getTokenType().toASCIIString() ); 
      
      ValidateTargetType validateTarget = rst1.getValidateTarget();
      AssertionType assertion = (AssertionType) validateTarget.getAny();
      assertEquals( "ID_654b6092-c725-40ea-8044-de453b59cb28", assertion.getID() );
   }

}
