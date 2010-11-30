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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Iterator;
import java.util.List;

import javax.xml.bind.JAXBElement;
 
import org.junit.Test;
import org.picketlink.identity.federation.core.parsers.saml.SAMLParser;
import org.picketlink.identity.federation.core.saml.v2.util.DocumentUtil;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.core.saml.v2.writers.SAMLResponseWriter;
import org.picketlink.identity.federation.core.util.StaxUtil; 
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AttributeStatementType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AttributeType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AuthnContextDeclRefType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AuthnContextType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AuthnStatementType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.StatementAbstractType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.SubjectConfirmationDataType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.SubjectConfirmationType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.SubjectType;
import org.picketlink.identity.federation.newmodel.saml.v2.protocol.*;
import org.picketlink.identity.federation.newmodel.saml.v2.protocol.ResponseType.RTChoiceType;

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
      
      List<RTChoiceType> assertionList = response.getAssertions();
      assertEquals( 2, assertionList.size() );
      
      AssertionType assertion1 = assertionList.get( 0 ).getAssertion();
      assertEquals( "ID_0be488d8-7089-4892-8aeb-83594c800706", assertion1.getID() );
      assertEquals( XMLTimeUtil.parse( "2009-05-26T14:06:26.362-05:00" ), assertion1.getIssueInstant() );
      assertEquals( "2.0", assertion1.getVersion() );
      assertEquals( "testIssuer", assertion1.getIssuer().getValue() ) ;
      
      Iterator<StatementAbstractType> iterator = assertion1.getStatements().iterator();
      
      AuthnStatementType authnStatement = (AuthnStatementType) iterator.next();
      assertEquals( XMLTimeUtil.parse( "2009-05-26T14:06:26.359-05:00" ), authnStatement.getAuthnInstant() );
      

      AuthnContextType authnContext = authnStatement.getAuthnContext();
      
      AuthnContextDeclRefType refType = (AuthnContextDeclRefType) authnContext.getURIType().iterator().next();
      assertEquals( "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", refType.getValue().toASCIIString() ); 
      /*
      JAXBElement<?> authnContextDeclRefJaxb = (JAXBElement<?>) authnStatement.getAuthnContext().getContent().get(0);
      assertEquals( "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", authnContextDeclRefJaxb.getValue() );*/
      
      
      AssertionType assertion2 = (AssertionType) assertionList.get( 1 ).getAssertion();
      assertEquals( "ID_976d8310-658a-450d-be39-f33c73c8afa6", assertion2.getID() );
      assertEquals( XMLTimeUtil.parse( "2009-05-26T14:06:26.363-05:00" ), assertion2.getIssueInstant() );
      assertEquals( "2.0", assertion2.getVersion() );
      assertEquals( "testIssuer", assertion2.getIssuer().getValue() );
      
      authnStatement = (AuthnStatementType) assertion2.getStatements().iterator().next();
      assertEquals( XMLTimeUtil.parse( "2009-05-26T14:06:26.359-05:00" ), authnStatement.getAuthnInstant() );
      authnContext = authnStatement.getAuthnContext();
      
      refType = (AuthnContextDeclRefType) authnContext.getURIType().iterator().next();
      assertEquals( "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", refType.getValue().toASCIIString() ); 
      
      //Let us do some writing - currently only visual inspection. We will do proper validation later.
      ByteArrayOutputStream baos = new ByteArrayOutputStream(); 
      SAMLResponseWriter writer = new SAMLResponseWriter(StaxUtil.getXMLStreamWriter(baos)); 
      writer.write(response );
      
      System.out.println( new String( baos.toByteArray() ));
      
      ByteArrayInputStream bis = new ByteArrayInputStream( baos.toByteArray() );
      DocumentUtil.getDocument( bis ); //throws exceptions
   }
   
   @Test
   public void testAssertionWithSubjectAndAttributes() throws Exception
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream configStream = tcl.getResourceAsStream( "parser/saml2/saml2-response-assertion-subject.xml" );
      
      SAMLParser parser = new SAMLParser();
      ResponseType response = ( ResponseType ) parser.parse(configStream);
      assertNotNull( response );
      
      assertEquals( "ID_45df1ea5-81e4-4147-a39a-43a4ef613f4e", response.getID() );
      assertEquals( XMLTimeUtil.parse( "2010-11-04T00:19:16.847-05:00" ), response.getIssueInstant() );
      assertEquals( "2.0", response.getVersion() );
      assertEquals( "http://localhost:8080/employee/", response.getDestination() );
      assertEquals( "ID_04ded476-d73c-48af-b3a9-232a52905ffb", response.getInResponseTo() );
      
      //Issuer
      assertEquals( "http://localhost:8080/idp/", response.getIssuer().getValue() );
      
      //Status
      StatusType status = response.getStatus();
      assertEquals( "urn:oasis:names:tc:SAML:2.0:status:Success", status.getStatusCode().getValue() );
      
      //Get the assertion
      AssertionType assertion = (AssertionType) response.getAssertions().get(0).getAssertion();
      assertEquals( "ID_8be1534d-9155-4837-9f26-70ea2c15e327", assertion.getID() );
      assertEquals( XMLTimeUtil.parse( "2010-11-04T00:19:16.842-05:00" ), assertion.getIssueInstant() );
      assertEquals( "2.0", assertion.getVersion() );
      
      assertEquals( "http://localhost:8080/idp/", assertion.getIssuer().getValue() );  
      
      //Subject
      SubjectType subject = assertion.getSubject();
      
      NameIDType subjectNameID = (NameIDType) subject.getSubType().getBaseID();
      assertEquals( "anil", subjectNameID.getValue() );
      assertEquals( "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", subjectNameID.getFormat() ); 
      
      SubjectConfirmationType subjectConfirmation = subject.getConfirmation().get(0);

      assertEquals( "urn:oasis:names:tc:SAML:2.0:cm:bearer", subjectConfirmation.getMethod() );
      
      SubjectConfirmationDataType subjectConfirmationData = subjectConfirmation.getSubjectConfirmationData();
      assertEquals( "ID_04ded476-d73c-48af-b3a9-232a52905ffb", subjectConfirmationData.getInResponseTo() );
      assertEquals( XMLTimeUtil.parse( "2010-11-04T00:19:16.842-05:00" ), subjectConfirmationData.getNotBefore() );
      assertEquals(  XMLTimeUtil.parse( "2010-11-04T00:19:16.842-05:00" ), subjectConfirmationData.getNotOnOrAfter() );
      assertEquals( "http://localhost:8080/employee/", subjectConfirmationData.getRecipient());
      
      AttributeStatementType attributeStatement = (AttributeStatementType)  assertion.getStatements().iterator().next();
      
      List<org.picketlink.identity.federation.newmodel.saml.v2.assertion.AttributeStatementType.ASTChoiceType> attributes = attributeStatement.getAttributes();
      assertEquals( 2, attributes.size() ); 
      
      for( org.picketlink.identity.federation.newmodel.saml.v2.assertion.AttributeStatementType.ASTChoiceType attr: attributes )
      {
         AttributeType attribute = attr.getAttribute();
         assertEquals( "role", attribute.getFriendlyName() );
         assertEquals( "role", attribute.getName() );
         assertEquals( "role", attribute.getNameFormat() );
         List<Object> attributeValues = attribute.getAttributeValue();
         assertEquals( 1, attributeValues.size() );
         
         String str = (String ) attributeValues.get( 0 ); 
         if( ! ( str.equals( "employee") || str.equals( "manager" )))
            throw new RuntimeException( "attrib value not found" );
      } 
      
      /*List<JAXBElement<?>> content = subject.getContent(); 
      
      int size = content.size();
      
      for( int i = 0 ; i < size; i++ )
      {
         JAXBElement<?> node = content.get(i);
         Class<?> clazz = node.getDeclaredType();
         
         if( clazz.equals( NameIDType.class ))
         {
            NameIDType subjectNameID = (NameIDType) node.getValue();
            
            assertEquals( "anil", subjectNameID.getValue() );
            assertEquals( "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", subjectNameID.getFormat() ); 
         }
         
         else if( clazz.equals( SubjectConfirmationType.class ))
         { 
            SubjectConfirmationType subjectConfirmation = (SubjectConfirmationType) node.getValue();
            assertEquals( "urn:oasis:names:tc:SAML:2.0:cm:bearer", subjectConfirmation.getMethod() );
            
            SubjectConfirmationDataType subjectConfirmationData = subjectConfirmation.getSubjectConfirmationData();
            assertEquals( "ID_04ded476-d73c-48af-b3a9-232a52905ffb", subjectConfirmationData.getInResponseTo() );
            assertEquals( XMLTimeUtil.parse( "2010-11-04T00:19:16.842-05:00" ), subjectConfirmationData.getNotBefore() );
            assertEquals(  XMLTimeUtil.parse( "2010-11-04T00:19:16.842-05:00" ), subjectConfirmationData.getNotOnOrAfter() );
            assertEquals( "http://localhost:8080/employee/", subjectConfirmationData.getRecipient());
         }
         
         else if( clazz.equals( AttributeStatementType.class ))
         {
            AttributeStatementType attributeStatement = (AttributeStatementType) node.getValue();
            List<Object> attributes = attributeStatement.getAttributeOrEncryptedAttribute();
            assertEquals( 2, attributes.size() ); 
            
            for( Object attr: attributes )
            {
               AttributeType attribute = (AttributeType) attr;
               assertEquals( "role", attribute.getFriendlyName() );
               assertEquals( "role", attribute.getName() );
               assertEquals( "role", attribute.getNameFormat() );
               List<Object> attributeValues = attribute.getAttributeValue();
               assertEquals( 1, attributeValues.size() );
               
               String str = (String ) attributeValues.get( 0 ); 
               if( ! ( str.equals( "employee") || str.equals( "manager" )))
                  throw new RuntimeException( "attrib value not found" );
            } 
         }
         else 
            throw new RuntimeException( "unknown" );
      } */
   }
}