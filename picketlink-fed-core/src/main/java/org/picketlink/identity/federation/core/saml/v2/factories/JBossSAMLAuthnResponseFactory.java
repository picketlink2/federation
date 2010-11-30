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

import java.util.List;

import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.datatype.XMLGregorianCalendar;

import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.saml.v2.holders.IDPInfoHolder;
import org.picketlink.identity.federation.core.saml.v2.holders.IssuerInfoHolder;
import org.picketlink.identity.federation.core.saml.v2.holders.SPInfoHolder;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.core.util.JAXBUtil;
import org.picketlink.identity.federation.core.util.NetworkUtil;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.ConditionsType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.StatementAbstractType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.SubjectConfirmationDataType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.SubjectConfirmationType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.SubjectType;
import org.picketlink.identity.federation.newmodel.saml.v2.protocol.ResponseType;
import org.picketlink.identity.federation.newmodel.saml.v2.protocol.ResponseType.RTChoiceType;
import org.picketlink.identity.federation.newmodel.saml.v2.protocol.StatusCodeType;
import org.picketlink.identity.federation.newmodel.saml.v2.protocol.StatusType;
import org.xml.sax.SAXException;

/**
 * Factory for the SAML v2 Authn Response
 * @author Anil.Saldhana@redhat.com
 * @since Dec 9, 2008
 */
public class JBossSAMLAuthnResponseFactory
{
   private static String pkgName = "org.picketlink.identity.federation.saml.v2.protocol:org.picketlink.identity.xmlsec.w3.xmldsig:org.picketlink.identity.xmlsec.w3.xmlenc";
   private static String schemaLocation = "schema/saml/v2/saml-schema-protocol-2.0.xsd";
   
   /**
    * Create a StatusType given the status code uri
    * @param statusCodeURI
    * @return
    */
   public static StatusType createStatusType(String statusCodeURI)
   {
      StatusCodeType sct = new StatusCodeType(); 
      sct.setValue( NetworkUtil.createURI( statusCodeURI ));
      
      StatusType statusType = new StatusType(); 
      statusType.setStatusCode(sct);
      return statusType;
   }
   
   /**
    * Create an empty response type
    * @return
    */
   public static ResponseType createResponseType()
   {
      return new ResponseType();
   }
   
   /**
    * Create a ResponseType
    * @param ID id of the response
    * @param sp holder with the information about the Service Provider
    * @param idp holder with the information on the Identity Provider
    * @param issuerInfo holder with information on the issuer
    * @return
    * @throws ConfigurationException   
    */
   public static ResponseType createResponseType(String ID, SPInfoHolder sp, IDPInfoHolder idp, 
         IssuerInfoHolder issuerInfo) throws ConfigurationException 
   {  
      String responseDestinationURI = sp.getResponseDestinationURI();
      
      XMLGregorianCalendar issueInstant = XMLTimeUtil.getIssueInstant(); 
      
      //Create an assertion
      String id = "ID_" + JBossSAMLBaseFactory.createUUID(); 
      
      //Create assertion -> subject
      SubjectType subjectType = new SubjectType();
      
      //subject -> nameid
      NameIDType nameIDType = new NameIDType();
      nameIDType.setFormat( NetworkUtil.createURI( idp.getNameIDFormat() ));
      nameIDType.setValue(idp.getNameIDFormatValue());
      
      SubjectType.STSubType subType = new SubjectType.STSubType();
      subType.addBaseID(nameIDType); 
      
      SubjectConfirmationType subjectConfirmation = new SubjectConfirmationType(); 
      subjectConfirmation.setMethod(  idp.getSubjectConfirmationMethod());
      
      SubjectConfirmationDataType subjectConfirmationData = new SubjectConfirmationDataType();
      subjectConfirmationData.setInResponseTo(  sp.getRequestID() );
      subjectConfirmationData.setRecipient( responseDestinationURI );
      subjectConfirmationData.setNotBefore(issueInstant);
      subjectConfirmationData.setNotOnOrAfter(issueInstant);
      
      subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

      subjectType.addConfirmation(subjectConfirmation);
      
      AssertionType assertionType = SAMLAssertionFactory.createAssertion(id, 
            nameIDType , issueInstant, (ConditionsType) null, subjectType, (List<StatementAbstractType>)null );
      
      
      ResponseType responseType = createResponseType(ID, issuerInfo, assertionType); 
      //InResponseTo ID
      responseType.setInResponseTo(sp.getRequestID());
      //Destination
      responseType.setDestination(responseDestinationURI);
       
      return responseType;
   } 
   
   /**
    * Create a Response Type
    * @param ID
    * @param issuerInfo
    * @param assertionType
    * @return
    * @throws ConfigurationException 
    */
   public static ResponseType createResponseType(String ID, IssuerInfoHolder issuerInfo, AssertionType assertionType) 
   throws ConfigurationException 
   {
      ResponseType responseType = new ResponseType();
      responseType.setVersion(issuerInfo.getSamlVersion());
      
      //ID
      responseType.setID(ID);
      
      //Issuer 
      NameIDType issuer = issuerInfo.getIssuer();
      responseType.setIssuer(issuer);
      
      //Status
      String statusCode = issuerInfo.getStatusCode();
      if(statusCode == null)
         throw new IllegalArgumentException("issuerInfo missing status code");
      
      responseType.setStatus(createStatusType(statusCode) );
      
      XMLGregorianCalendar issueInstant = XMLTimeUtil.getIssueInstant(); 
      
      //IssueInstant
      responseType.setIssueInstant(issueInstant); 
      
      responseType.addAssertion( new RTChoiceType( assertionType )); 
      return responseType; 
   }
   
   /**
    * Get the JAXB2 marshaller
    * @return 
    * @throws JAXBException 
    * @throws SAXException 
    */
   public static Marshaller getMarshaller() throws SAXException, JAXBException 
   {
      return JAXBUtil.getMarshaller(pkgName);
   }

   /**
    * Get the JAXB2 Unmarshaller
    * @return
    * @throws SAXException 
    * @throws JAXBException  
    */
   public static Unmarshaller getUnmarshaller() throws JAXBException, SAXException 
   {
      return JAXBUtil.getUnmarshaller(pkgName);
   }
   
   /**
    * Get the validating marshaller
    * 
    * @param schemaValidation Whether schema validation is needed
    * @return
    * @throws JAXBException
    * @throws SAXException
    */
   public static Marshaller getValidatingMarshaller(boolean schemaValidation) throws SAXException, JAXBException
   {
      if (schemaValidation)
         return JAXBUtil.getValidatingMarshaller(pkgName, schemaLocation);
      else
         return JAXBUtil.getMarshaller(pkgName);
   }

   /**
    * Get the JAXB2 Unmarshaller
    * @return
    * @throws SAXException 
    * @throws JAXBException  
    */
   public static Unmarshaller getValidatingUnmarshaller() throws JAXBException, SAXException 
   {
      return JAXBUtil.getValidatingUnmarshaller(pkgName, schemaLocation);
   }
}