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
package org.picketlink.identity.federation.core.saml.v2.factories;


import javax.xml.bind.JAXBElement;
import javax.xml.datatype.XMLGregorianCalendar;

import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.ObjectFactory;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectConfirmationDataType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectConfirmationType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;

/**
 * Base methods for the factories
 * @author Anil.Saldhana@redhat.com
 * @since Dec 9, 2008
 */
public class JBossSAMLBaseFactory
{
   private static ObjectFactory assertionObjectFactory = new ObjectFactory();
  
   /**
    * Create a plain assertion type
    * @return
    */
   public static AssertionType createAssertion()
   {
      return assertionObjectFactory.createAssertionType();  
   }
   
   /**
    * Create an empty attribute statement
    * @return
    */
   public static AttributeStatementType createAttributeStatement()
   {
      return assertionObjectFactory.createAttributeStatementType();
   }
   
   /**
    * Create an attribute type given a role name
    * @param roleName
    * @return
    */
   public static AttributeType createAttributeForRole(String roleName)
   {
      AttributeType att = assertionObjectFactory.createAttributeType();
      att.setFriendlyName("role");
      att.setName("role");
      att.setNameFormat(JBossSAMLURIConstants.ATTRIBUTE_FORMAT_BASIC.get());
      
      //rolename 
      att.getAttributeValue().add(roleName);
      
      return att;
   }
   
   /**
    * Create an AttributeStatement given an attribute
    * @param attributeValue
    * @return
    */
   public static AttributeStatementType createAttributeStatement(String attributeValue)
   {
      AttributeStatementType attribStatement = assertionObjectFactory.createAttributeStatementType();
      AttributeType att = assertionObjectFactory.createAttributeType();
      JAXBElement<Object> attValue = assertionObjectFactory.createAttributeValue(attributeValue);
      att.getAttributeValue().add(attValue);
      attribStatement.getAttributeOrEncryptedAttribute().add(att);
      return attribStatement;
   }
   
   /**
    * Create an empty name id
    * @return
    */
   public static NameIDType createNameID()
   {
      return assertionObjectFactory.createNameIDType();
   }
   
   /**
    * Create the JAXBElement type of nameid
    * @param nameIDType
    * @return
    */
   public static JAXBElement<NameIDType> createNameID(NameIDType nameIDType)
   {
      return assertionObjectFactory.createNameID(nameIDType);
   }
   
   /**
    * Create an empty subject
    * @return
    */
   public static SubjectType createSubject()
   {
      SubjectType subjectType = assertionObjectFactory.createSubjectType();
      return subjectType;
   }
   
   /**
    * Create a Subject confirmation type given the method
    * @param method
    * @return
    */
   public static SubjectConfirmationType createSubjectConfirmation(String method)
   {
      SubjectConfirmationType sct = assertionObjectFactory.createSubjectConfirmationType();
      sct.setMethod(method);
      return sct;
   }
   
   /**
    * Create a JAXBElement for subject confirmtation type
    * @param sct
    * @return
    */
   
   public static JAXBElement<SubjectConfirmationType> createSubjectConfirmation(SubjectConfirmationType sct)
   {
      return assertionObjectFactory.createSubjectConfirmation(sct);
   }
   
   /**
    * Create a Subject Confirmation
    * @param inResponseTo
    * @param destinationURI
    * @param issueInstant
    * @return
    */
   public static SubjectConfirmationDataType createSubjectConfirmationData(String inResponseTo, 
         String destinationURI, XMLGregorianCalendar issueInstant)
   {
      SubjectConfirmationDataType subjectConfirmationData = assertionObjectFactory.createSubjectConfirmationDataType();
      subjectConfirmationData.setInResponseTo(inResponseTo);
      subjectConfirmationData.setRecipient(destinationURI);
      subjectConfirmationData.setNotBefore(issueInstant);
      subjectConfirmationData.setNotOnOrAfter(issueInstant);
      
      return subjectConfirmationData;
   }
   
   /**
    * Get a UUID String
    * @return
    */
   public static String createUUID()
   {
      return java.util.UUID.randomUUID().toString(); 
   }
   
   /**
    * Get the Object Factory
    * @return
    */
   public static ObjectFactory getObjectFactory()
   {
      return assertionObjectFactory;
   }
   
   /**
    * Return the NameIDType for the issuer
    * @param issuerID
    * @return
    */
   public static NameIDType getIssuer(String issuerID)
   {
      NameIDType nid = assertionObjectFactory.createNameIDType();
      nid.setValue(issuerID);
      return nid;
   }
}