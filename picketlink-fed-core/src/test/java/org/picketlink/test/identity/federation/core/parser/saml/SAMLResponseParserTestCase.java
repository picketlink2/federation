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
package org.picketlink.test.identity.federation.core.parser.saml;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.InputStream;
import java.util.List;

import javax.xml.bind.JAXBElement;

import org.junit.Test;
import org.picketlink.identity.federation.core.parsers.saml.SAMLParser;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.AuthnStatementType;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusType;

/**
 * Validate the parsing of SAML2 Response
 * @author Anil.Saldhana@redhat.com
 * @since Nov 2, 2010
 */
public class SAMLResponseParserTestCase
{
   @Test
   public void testSAMLResponseParse() throws Exception
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream configStream = tcl.getResourceAsStream( "parser/saml2/saml2-response.xml" );
      
      SAMLParser parser = new SAMLParser();
      ResponseType response = ( ResponseType ) parser.parse(configStream);
      assertNotNull( "ResponseType is not null", response ); 
      
      assertEquals( XMLTimeUtil.parse( "2009-05-26T14:06:26.362-05:00" ), response.getIssueInstant() );
      assertEquals( "2.0", response.getVersion() );
      assertEquals( "ID_1164e0fc-576d-4797-b11c-3d049520f566", response.getID() ); 
      
      //Issuer
      assertEquals( "testIssuer", response.getIssuer().getValue() );
      
      //Status
      StatusType status = response.getStatus();
      assertEquals( "urn:oasis:names:tc:SAML:2.0:status:Success", status.getStatusCode().getValue() );
      
      List<Object> assertionList = response.getAssertionOrEncryptedAssertion();
      assertEquals( 2, assertionList.size() );
      
      AssertionType assertion1 = (AssertionType) assertionList.get( 0 );
      assertEquals( "ID_0be488d8-7089-4892-8aeb-83594c800706", assertion1.getID() );
      assertEquals( XMLTimeUtil.parse( "2009-05-26T14:06:26.362-05:00" ), assertion1.getIssueInstant() );
      assertEquals( "2.0", assertion1.getVersion() );
      assertEquals( "testIssuer", assertion1.getIssuer().getValue() );
      AuthnStatementType authnStatement = (AuthnStatementType) assertion1.getStatementOrAuthnStatementOrAuthzDecisionStatement().get( 0 );
      assertEquals( XMLTimeUtil.parse( "2009-05-26T14:06:26.359-05:00" ), authnStatement.getAuthnInstant() );
      JAXBElement<?> authnContextDeclRefJaxb = (JAXBElement<?>) authnStatement.getAuthnContext().getContent().get(0);
      assertEquals( "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", authnContextDeclRefJaxb.getValue() );
      
      
      AssertionType assertion2 = (AssertionType) assertionList.get( 1 );
      assertEquals( "ID_976d8310-658a-450d-be39-f33c73c8afa6", assertion2.getID() );
      assertEquals( XMLTimeUtil.parse( "2009-05-26T14:06:26.363-05:00" ), assertion2.getIssueInstant() );
      assertEquals( "2.0", assertion2.getVersion() );
      assertEquals( "testIssuer", assertion2.getIssuer().getValue() );
      
      authnStatement = (AuthnStatementType) assertion2.getStatementOrAuthnStatementOrAuthzDecisionStatement().get( 0 );
      assertEquals( XMLTimeUtil.parse( "2009-05-26T14:06:26.359-05:00" ), authnStatement.getAuthnInstant() );
      authnContextDeclRefJaxb = (JAXBElement<?>) authnStatement.getAuthnContext().getContent().get(0);
      assertEquals( "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", authnContextDeclRefJaxb.getValue() ); 
   }
}