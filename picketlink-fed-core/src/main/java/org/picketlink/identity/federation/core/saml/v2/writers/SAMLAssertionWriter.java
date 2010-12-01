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

import java.net.URI;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamWriter;

import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLConstants;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.core.util.StaxUtil;
import org.picketlink.identity.federation.core.util.StringUtil;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AdviceType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AttributeStatementType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AttributeStatementType.ASTChoiceType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AttributeType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AudienceRestrictionType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AuthnContextClassRefType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AuthnContextDeclRefType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AuthnContextDeclType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AuthnContextType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AuthnContextType.AuthnContextTypeSequence;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AuthnStatementType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.BaseIDAbstractType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.ConditionAbstractType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.ConditionsType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.EncryptedElementType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.StatementAbstractType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.SubjectConfirmationDataType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.SubjectConfirmationType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.SubjectType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.SubjectType.STSubType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.URIType;

/**
 * Write the SAML Assertion to stream
 * @author Anil.Saldhana@redhat.com
 * @since Nov 2, 2010
 */
public class SAMLAssertionWriter extends BaseWriter
{
   public SAMLAssertionWriter(XMLStreamWriter writer) throws ProcessingException
   {
      super(writer);
   }
   
   /**
    * Write an {@code AssertionType} to stream
    * @param assertion
    * @param out
    * @throws ProcessingException
    */
   public void write( AssertionType assertion ) throws ProcessingException
   {
      StaxUtil.writeStartElement( writer, ASSERTION_PREFIX, JBossSAMLConstants.ASSERTION.get() , ASSERTION_NSURI.get() ); 
      StaxUtil.writeNameSpace( writer, ASSERTION_PREFIX, ASSERTION_NSURI.get() );
      StaxUtil.writeDefaultNameSpace( writer, ASSERTION_NSURI.get() );

      //Attributes 
      StaxUtil.writeAttribute( writer, JBossSAMLConstants.ID.get(), assertion.getID() );
      StaxUtil.writeAttribute( writer, JBossSAMLConstants.VERSION.get(), assertion.getVersion() );
      StaxUtil.writeAttribute( writer, JBossSAMLConstants.ISSUE_INSTANT.get(), assertion.getIssueInstant().toString() );     

      NameIDType issuer = assertion.getIssuer();
      if( issuer != null )
         write( issuer, new QName( ASSERTION_NSURI.get(), JBossSAMLConstants.ISSUER.get() ) ); 
      
      SubjectType subject = assertion.getSubject();
      if( subject != null )
      {
         write(subject);
      }
      
      ConditionsType conditions = assertion.getConditions();
      if( conditions != null )
      {
         StaxUtil.writeStartElement( writer, ASSERTION_PREFIX, JBossSAMLConstants.CONDITIONS.get() , ASSERTION_NSURI.get() ); 
         
         StaxUtil.writeAttribute( writer, JBossSAMLConstants.NOT_BEFORE.get(), conditions.getNotBefore().toString() );
         StaxUtil.writeAttribute( writer, JBossSAMLConstants.NOT_ON_OR_AFTER.get(), conditions.getNotOnOrAfter().toString() );
         
         List<ConditionAbstractType> typeOfConditions = conditions.getConditions();
         if( typeOfConditions != null )
         {
            for( ConditionAbstractType typeCondition: typeOfConditions )
            {
               if( typeCondition instanceof AudienceRestrictionType )
               {
                  AudienceRestrictionType art = (AudienceRestrictionType) typeCondition;
                  StaxUtil.writeStartElement( writer, ASSERTION_PREFIX, JBossSAMLConstants.AUDIENCE_RESTRICTION.get() , ASSERTION_NSURI.get() ); 
                  List<URI> audiences = art.getAudience();
                  if( audiences != null )
                  {
                     for( URI audience: audiences )
                     {
                        StaxUtil.writeStartElement( writer, ASSERTION_PREFIX, JBossSAMLConstants.AUDIENCE.get() , ASSERTION_NSURI.get() );
                        StaxUtil.writeCharacters(writer, audience.toString() );
                        StaxUtil.writeEndElement( writer);
                     }
                  }

                  StaxUtil.writeEndElement( writer);  
               }
            }
         }

         StaxUtil.writeEndElement( writer); 
      }
      
      AdviceType advice = assertion.getAdvice();
      if( advice != null )
         throw new RuntimeException( "Advice needs to be handled" );
      
      Set<StatementAbstractType> statements = assertion.getStatements();
      if( statements != null )
      {
         for( StatementAbstractType statement: statements )
         {
            if( statement instanceof AuthnStatementType )
            {
               write( ( AuthnStatementType )statement );
            }
            else if( statement instanceof AttributeStatementType )
            {
               write( ( AttributeStatementType )statement );
            }
            else 
                throw new RuntimeException( "unknown statement type=" + statement.getClass().getName() ); 
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
   public void write( StatementAbstractType statement ) throws ProcessingException
   {
      //TODO: handle this section
   }
   
   public void write( AttributeStatementType statement ) throws ProcessingException
   {
      StaxUtil.writeStartElement( writer, ASSERTION_PREFIX, JBossSAMLConstants.ATTRIBUTE_STATEMENT.get() , ASSERTION_NSURI.get() );  
      
      List<ASTChoiceType> attributes = statement.getAttributes();
      if( attributes != null )
      {
         for( ASTChoiceType attr : attributes )
         {
            AttributeType attributeType = attr.getAttribute();
            if( attributeType != null ) 
            {
               write( attributeType );
            }
            EncryptedElementType encType = attr.getEncryptedAssertion();
            if( encType != null )
               throw new RuntimeException( "unable to write as it is NYI" );
         }
      } 

      StaxUtil.writeEndElement( writer); 
      StaxUtil.flush( writer );  
   }
   
   
   /**
    * Write an {@code AuthnStatementType} to stream
    * @param authnStatement
    * @param out
    * @throws ProcessingException
    */
   public void write( AuthnStatementType authnStatement ) throws ProcessingException
   {
      StaxUtil.writeStartElement( writer, ASSERTION_PREFIX, JBossSAMLConstants.AUTHN_STATEMENT.get() , ASSERTION_NSURI.get() );  
      
      XMLGregorianCalendar authnInstant = authnStatement.getAuthnInstant();
      if( authnInstant != null )
      { 
         StaxUtil.writeAttribute( writer, JBossSAMLConstants.AUTHN_INSTANT.get(), authnInstant.toString() );
      }
      
      AuthnContextType authnContext = authnStatement.getAuthnContext();
      if( authnContext != null )
        write( authnContext );

      StaxUtil.writeEndElement( writer); 
      StaxUtil.flush( writer );  
   }
   
   /**
    * Write an {@code AuthnContextType} to stream
    * @param authContext
    * @param out
    * @throws ProcessingException
    */
   public void write( AuthnContextType authContext ) throws ProcessingException
   {
      StaxUtil.writeStartElement( writer, ASSERTION_PREFIX, JBossSAMLConstants.AUTHN_CONTEXT.get() , ASSERTION_NSURI.get() );  
      
      AuthnContextTypeSequence sequence = authContext.getSequence();
      if( sequence != null )
      {
         AuthnContextClassRefType authnContextClassRefType = sequence.getClassRef();
         if( authnContextClassRefType != null )
         {
            StaxUtil.writeStartElement( writer, ASSERTION_PREFIX, JBossSAMLConstants.AUTHN_CONTEXT_CLASS_REF.get() ,
                  ASSERTION_NSURI.get() ); 
            StaxUtil.writeCharacters( writer,  authnContextClassRefType.getValue().toASCIIString() ); 
            StaxUtil.writeEndElement( writer);  
         } 
         
         Set<URIType> uriTypes = sequence.getURIType();
         if( uriTypes != null )
         {
            for( URIType uriType: uriTypes )
            {
               if( uriType instanceof AuthnContextDeclType )
               {
                  StaxUtil.writeStartElement( writer, ASSERTION_PREFIX, JBossSAMLConstants.AUTHN_CONTEXT_DECLARATION.get() ,
                        ASSERTION_NSURI.get() );  
                  StaxUtil.writeCharacters( writer, uriType.getValue().toASCIIString() );
                  StaxUtil.writeEndElement( writer);  
               }
               if( uriType instanceof AuthnContextDeclRefType )
               {
                  StaxUtil.writeStartElement( writer, ASSERTION_PREFIX, JBossSAMLConstants.AUTHN_CONTEXT_DECLARATION_REF.get() ,
                        ASSERTION_NSURI.get() );  
                  StaxUtil.writeCharacters( writer, uriType.getValue().toASCIIString() );
                  StaxUtil.writeEndElement( writer);  
               }
            }
         } 
      }
      
      Set<URI> authAuthorities = authContext.getAuthenticatingAuthority();
      if( authAuthorities != null )
      {
         for( URI aa: authAuthorities )
         {
            StaxUtil.writeStartElement( writer, ASSERTION_PREFIX, JBossSAMLConstants.AUTHENTICATING_AUTHORITY.get() ,
                  ASSERTION_NSURI.get() );  
            StaxUtil.writeCharacters( writer, aa.toASCIIString() );
            StaxUtil.writeEndElement( writer);   
         }
      } 

      StaxUtil.writeEndElement( writer); 
      StaxUtil.flush( writer );  
   }
   
   /**
    * Write an {@code AttributeType} to stream
    * @param attributeType
    * @param out
    * @throws ProcessingException
    */
   public void write( AttributeType attributeType ) throws ProcessingException
   {
      StaxUtil.writeStartElement( writer, ASSERTION_PREFIX, JBossSAMLConstants.ATTRIBUTE.get() , ASSERTION_NSURI.get() );  

      String attributeName = attributeType.getName();
      if( attributeName != null )
      {
         StaxUtil.writeAttribute( writer, JBossSAMLConstants.NAME.get(), attributeName );
      }
      
      String friendlyName = attributeType.getFriendlyName();
      if( StringUtil.isNotNull( friendlyName ))
      {
         StaxUtil.writeAttribute( writer, JBossSAMLConstants.FRIENDLY_NAME.get(), friendlyName );
      }
      
      String nameFormat = attributeType.getNameFormat();
      if( StringUtil.isNotNull( nameFormat ))
      {
         StaxUtil.writeAttribute( writer, JBossSAMLConstants.NAME_FORMAT.get(), friendlyName );
      }
      
      //Take care of other attributes such as x500:encoding
      Map<QName, String> otherAttribs = attributeType.getOtherAttributes();
      if( otherAttribs != null )
      {
         List<String> nameSpacesDealt = new ArrayList<String>();
         
         Iterator<QName> keySet = otherAttribs.keySet().iterator();
         while( keySet != null && keySet.hasNext() )
         {
            QName qname = keySet.next();
            String ns = qname.getNamespaceURI();
            if( !nameSpacesDealt.contains( ns ))
            {
               StaxUtil.writeNameSpace(writer, qname.getPrefix(), ns );
               nameSpacesDealt.add( ns );
            } 
            String attribValue = otherAttribs.get( qname );
            StaxUtil.writeAttribute(writer, qname, attribValue );
         }
      }
      
      List<Object> attributeValues = attributeType.getAttributeValue();
      if( attributeValues != null )
      {
         for( Object attributeValue : attributeValues )
         {
            if( attributeValue instanceof String )
            {  
               StaxUtil.writeStartElement( writer, ASSERTION_PREFIX, JBossSAMLConstants.ATTRIBUTE_VALUE.get() , ASSERTION_NSURI.get() );

               StaxUtil.writeNameSpace( writer, "xsi", JBossSAMLURIConstants.XSI_NSURI.get() ); 
               StaxUtil.writeNameSpace( writer, "xs", JBossSAMLURIConstants.XMLSCHEMA_NSURI.get() ); 
               StaxUtil.writeAttribute( writer, JBossSAMLURIConstants.XSI_NSURI.get(), "type", "xs:string");
               StaxUtil.writeCharacters(writer, (String) attributeValue );

               StaxUtil.writeEndElement( writer);
            }
            else 
               throw new RuntimeException( "Unsupported attribute value:" + attributeValue.getClass().getName() );
         }
      }
      StaxUtil.writeEndElement( writer); 
      StaxUtil.flush( writer );  
   }
   
   /**
    * write an {@code SubjectType} to stream
    * @param subject
    * @param out
    * @throws ProcessingException
    */
   public void write( SubjectType subject ) throws ProcessingException
   {
      StaxUtil.writeStartElement( writer, ASSERTION_PREFIX, JBossSAMLConstants.SUBJECT.get() , ASSERTION_NSURI.get() ); 
      
      STSubType subType = subject.getSubType();
      if( subType != null )
      {
         BaseIDAbstractType baseID = subType.getBaseID();
         if( baseID instanceof NameIDType )
         {
            NameIDType nameIDType = (NameIDType) baseID;
            write( nameIDType, new QName( ASSERTION_NSURI.get(), JBossSAMLConstants.NAMEID.get(), ASSERTION_PREFIX) ); 
         }
         EncryptedElementType enc = subType.getEncryptedID();
         if( enc != null )
            throw new RuntimeException( "NYI" );
         List<SubjectConfirmationType> confirmations = subType.getConfirmation();
         if( confirmations != null )
         {
            for( SubjectConfirmationType confirmation: confirmations )
            {
               write( confirmation );
            }
         }
      }
      List<SubjectConfirmationType> subjectConfirmations = subject.getConfirmation();
      if( subjectConfirmations != null )
      {
         for( SubjectConfirmationType subjectConfirmationType : subjectConfirmations )
         {
            write( subjectConfirmationType );  
         }
      }
       

      StaxUtil.writeEndElement( writer); 
      StaxUtil.flush( writer );  
   }
   
   private void write( BaseIDAbstractType baseId ) throws ProcessingException
   {
      throw new RuntimeException( "NYI");
   }
   
   private void write( SubjectConfirmationType subjectConfirmationType ) throws ProcessingException
   {
      StaxUtil.writeStartElement( writer, ASSERTION_PREFIX, JBossSAMLConstants.SUBJECT_CONFIRMATION.get(), ASSERTION_NSURI.get() );
      
      StaxUtil.writeAttribute(writer, JBossSAMLConstants.METHOD.get(), subjectConfirmationType.getMethod() );
      
      BaseIDAbstractType baseID = subjectConfirmationType.getBaseID();
      if( baseID != null )
      {
         write( baseID );
      }
      NameIDType nameIDType = subjectConfirmationType.getNameID();
      if( nameIDType != null )
      {
         write( nameIDType, new QName( ASSERTION_NSURI.get(), JBossSAMLConstants.NAMEID.get(), ASSERTION_PREFIX) );
      }
      SubjectConfirmationDataType subjectConfirmationData = subjectConfirmationType.getSubjectConfirmationData();
      if( subjectConfirmationData != null )
      {
         write( subjectConfirmationData ); 
      }  
      StaxUtil.writeEndElement( writer);
   }
   
   private void write( SubjectConfirmationDataType subjectConfirmationData ) throws ProcessingException
   {
      StaxUtil.writeStartElement( writer, ASSERTION_PREFIX, JBossSAMLConstants.SUBJECT_CONFIRMATION_DATA.get(), ASSERTION_NSURI.get() );  
      
      //Let us look at attributes
      String inResponseTo = subjectConfirmationData.getInResponseTo();
      if( StringUtil.isNotNull( inResponseTo ))
      {
         StaxUtil.writeAttribute(writer, JBossSAMLConstants.IN_RESPONSE_TO.get(), inResponseTo );
      }
      
      XMLGregorianCalendar notBefore = subjectConfirmationData.getNotBefore();
      if( notBefore != null )
      {
         StaxUtil.writeAttribute(writer, JBossSAMLConstants.NOT_BEFORE.get(),notBefore.toString() );
      }
      
      XMLGregorianCalendar notOnOrAfter = subjectConfirmationData.getNotOnOrAfter();
      if( notOnOrAfter != null )
      {
         StaxUtil.writeAttribute(writer, JBossSAMLConstants.NOT_ON_OR_AFTER.get(),notOnOrAfter.toString() );
      }
      
      String recipient = subjectConfirmationData.getRecipient();
      if( StringUtil.isNotNull( recipient ))
      {
         StaxUtil.writeAttribute(writer, JBossSAMLConstants.RECIPIENT.get(), recipient );
      }
      
      String address = subjectConfirmationData.getAddress();
      if( StringUtil.isNotNull( address ))
      {
         StaxUtil.writeAttribute(writer, JBossSAMLConstants.ADDRESS.get(), address );
      }

      StaxUtil.writeEndElement( writer); 
      StaxUtil.flush( writer );  
   }
}