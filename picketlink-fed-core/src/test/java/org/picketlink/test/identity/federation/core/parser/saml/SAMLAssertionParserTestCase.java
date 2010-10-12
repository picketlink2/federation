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
import javax.xml.datatype.DatatypeFactory;

import org.junit.Test;
import org.picketlink.identity.federation.core.parsers.saml.SAMLParser;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.ConditionsType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;

/**
 * @author Anil.Saldhana@redhat.com
 * @since Oct 12, 2010
 */
public class SAMLAssertionParserTestCase
{
   @Test
   public void testSAMLAssertionParsing() throws Exception
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream configStream = tcl.getResourceAsStream( "parser/saml2/saml2-assertion.xml" );
      
      SAMLParser parser = new SAMLParser();
      AssertionType assertion = (AssertionType) parser.parse(configStream);
      assertNotNull( assertion );
      //Issuer
      assertEquals( "Test STS", assertion.getIssuer().getValue() );
      
      //Subject
      SubjectType subject = assertion.getSubject();
      List<JAXBElement<?>> content = subject.getContent();
      

      DatatypeFactory dtf = DatatypeFactory.newInstance(); 
      
      int size = content.size();
      
      for( int i = 0 ; i < size; i++ )
      {
         JAXBElement<?> node = content.get(i);
         if( node.getDeclaredType().equals( NameIDType.class ))
         {
            NameIDType subjectNameID = (NameIDType) node.getValue();
            
            assertEquals( "jduke", subjectNameID.getValue() );
            assertEquals( "urn:picketlink:identity-federation", subjectNameID.getNameQualifier() ); 
         }
         
         if( node.getDeclaredType().equals( ConditionsType.class ))
         {

            //Conditions
            ConditionsType conditions =  (ConditionsType) node.getValue();
            assertEquals( dtf.newXMLGregorianCalendar( "2010-09-30T19:13:37.869Z" ) , conditions.getNotBefore() );
            assertEquals( dtf.newXMLGregorianCalendar( "2010-09-30T21:13:37.869Z" ) , conditions.getNotOnOrAfter() );
            
         }
      } 
   } 
}