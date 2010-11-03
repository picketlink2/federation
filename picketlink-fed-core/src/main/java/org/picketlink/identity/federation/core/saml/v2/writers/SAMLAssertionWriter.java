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
package org.picketlink.identity.federation.core.saml.v2.writers;

import static org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants.ASSERTION_NSURI;

import java.io.OutputStream;
import java.util.List;

import javax.xml.bind.JAXBElement;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;

import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLConstants;
import org.picketlink.identity.federation.core.util.StaxUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.AuthnContextType;
import org.picketlink.identity.federation.saml.v2.assertion.AuthnStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.StatementAbstractType;

/**
 * Write the SAML Assertion to stream
 * @author Anil.Saldhana@redhat.com
 * @since Nov 2, 2010
 */
public class SAMLAssertionWriter extends BaseWriter
{
   /**
    * Write an {@code AssertionType} to stream
    * @param assertion
    * @param out
    * @throws ProcessingException
    */
   public void write( AssertionType assertion, OutputStream out ) throws ProcessingException
   {
      verifyWriter( out ); 

      StaxUtil.writeStartElement( writer, ASSERTION_PREFIX, JBossSAMLConstants.ASSERTION.get() , ASSERTION_NSURI.get() ); 
      StaxUtil.writeNameSpace( writer, ASSERTION_PREFIX, ASSERTION_NSURI.get() );
      StaxUtil.WriteDefaultNameSpace( writer, ASSERTION_NSURI.get() );

      //Attributes 
      StaxUtil.writeAttribute( writer, JBossSAMLConstants.ID.get(), assertion.getID() );
      StaxUtil.writeAttribute( writer, JBossSAMLConstants.VERSION.get(), assertion.getVersion() );
      StaxUtil.writeAttribute( writer, JBossSAMLConstants.ISSUE_INSTANT.get(), assertion.getIssueInstant().toString() );     

      NameIDType issuer = assertion.getIssuer();
      write( issuer, new QName( ASSERTION_NSURI.get(), JBossSAMLConstants.ISSUER.get() ), out ); 
      
      List<StatementAbstractType> statements = assertion.getStatementOrAuthnStatementOrAuthzDecisionStatement();
      if( statements != null )
      {
         for( StatementAbstractType statement: statements )
         {
            if( statement instanceof AuthnStatementType )
            {
               write( ( AuthnStatementType )statement, out );
            }
            else write( statement, out );
         }
      }
      StaxUtil.writeEndElement( writer); 
      StaxUtil.flush( writer );  
   } 
   
   /**
    * Write an {@code StatementAbstractType} to stream
    * @param statement
    * @param out
    * @throws ProcessingException
    */
   public void write( StatementAbstractType statement, OutputStream out ) throws ProcessingException
   {
      verifyWriter( out );
      //TODO: handle this section
   }
   
   /**
    * Write an {@code AuthnStatementType} to stream
    * @param authnStatement
    * @param out
    * @throws ProcessingException
    */
   public void write( AuthnStatementType authnStatement, OutputStream out ) throws ProcessingException
   {
      verifyWriter( out );
      StaxUtil.writeStartElement( writer, ASSERTION_PREFIX, JBossSAMLConstants.AUTHN_STATEMENT.get() , ASSERTION_NSURI.get() );  
      
      XMLGregorianCalendar authnInstant = authnStatement.getAuthnInstant();
      if( authnInstant != null )
      { 
         StaxUtil.writeAttribute( writer, JBossSAMLConstants.AUTHN_INSTANT.get(), authnInstant.toString() );
      }
      
      AuthnContextType authnContext = authnStatement.getAuthnContext();
      if( authnContext != null )
        write( authnContext, out );

      StaxUtil.writeEndElement( writer); 
      StaxUtil.flush( writer );  
   }
   
   /**
    * Write an {@code AuthnContextType} to stream
    * @param authContext
    * @param out
    * @throws ProcessingException
    */
   public void write( AuthnContextType authContext, OutputStream out ) throws ProcessingException
   {
      verifyWriter( out );
      StaxUtil.writeStartElement( writer, ASSERTION_PREFIX, JBossSAMLConstants.AUTHN_CONTEXT.get() , ASSERTION_NSURI.get() );  
      
      List< JAXBElement<?> > subList = authContext.getContent();
      if( subList != null )
      {
         for( JAXBElement<?> el: subList )
         {
            QName elName = el.getName();
            if( elName.getLocalPart().equals( JBossSAMLConstants.AUTHN_CONTEXT_DECLARATION_REF.get() ))
            {
               String decl = (String) el.getValue();
               StaxUtil.writeStartElement( writer, ASSERTION_PREFIX, JBossSAMLConstants.AUTHN_CONTEXT_DECLARATION_REF.get() ,
                     ASSERTION_NSURI.get() );  
               StaxUtil.writeCharacters( writer, decl );
               StaxUtil.writeEndElement( writer);  
            }  
            else
               throw new RuntimeException( "Unsupported :" + elName );
         }
      }
   }
}