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

import org.junit.Test;
import org.picketlink.identity.federation.core.parsers.saml.SAMLParser;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusType;

/**
 * Validate the parsing of SLO Response
 * @author Anil.Saldhana@redhat.com
 * @since Nov 3, 2010
 */
public class SAMLSloResponseParserTestCase
{
   @Test
   public void testSAMLResponseParse() throws Exception
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream configStream = tcl.getResourceAsStream( "parser/saml2/saml2-logout-response.xml" );
      
      SAMLParser parser = new SAMLParser();
      ResponseType response = ( ResponseType ) parser.parse(configStream);
      assertNotNull( "ResponseType is not null", response ); 
      
      assertEquals( XMLTimeUtil.parse( "2010-07-29T13:46:03.862-05:00" ), response.getIssueInstant() );
      assertEquals( "2.0", response.getVersion() );
      assertEquals( "ID_97d332a8-3224-4653-a1ff-65c966e56852", response.getID() ); 
      
      //Issuer
      assertEquals( "http://localhost:8080/employee-post/", response.getIssuer().getValue() );
      
      //Status
      StatusType status = response.getStatus();
      assertEquals( "urn:oasis:names:tc:SAML:2.0:status:Responder", status.getStatusCode().getValue() );
      assertEquals( "urn:oasis:names:tc:SAML:2.0:status:Success", status.getStatusCode().getStatusCode().getValue() );
   } 
}