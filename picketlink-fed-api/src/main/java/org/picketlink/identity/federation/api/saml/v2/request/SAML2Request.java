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
package org.picketlink.identity.federation.api.saml.v2.request;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Writer;

import javax.xml.bind.Binder;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.ParserConfigurationException;

import org.picketlink.identity.federation.core.constants.PicketLinkFederationConstants;
import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.parsers.saml.SAMLParser;
import org.picketlink.identity.federation.core.saml.v2.common.IDGenerator;
import org.picketlink.identity.federation.core.saml.v2.common.SAMLDocumentHolder;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLConstants;
import org.picketlink.identity.federation.core.saml.v2.factories.JBossSAMLAuthnRequestFactory;
import org.picketlink.identity.federation.core.saml.v2.factories.JBossSAMLBaseFactory;
import org.picketlink.identity.federation.core.saml.v2.util.DocumentUtil;
import org.picketlink.identity.federation.core.saml.v2.util.JAXBElementMappingUtil;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.core.saml.v2.writers.SAMLRequestWriter;
import org.picketlink.identity.federation.core.util.JAXBUtil;
import org.picketlink.identity.federation.core.util.StaxUtil;
import org.picketlink.identity.federation.saml.v2.SAML2Object;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.profiles.xacml.protocol.XACMLAuthzDecisionQueryType;
import org.picketlink.identity.federation.saml.v2.protocol.AuthnRequestType;
import org.picketlink.identity.federation.saml.v2.protocol.LogoutRequestType;
import org.picketlink.identity.federation.saml.v2.protocol.RequestAbstractType;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

/**
 * API for SAML2 Request
 * @author Anil.Saldhana@redhat.com
 * @since Jan 5, 2009
 */
public class SAML2Request
{
   private SAMLDocumentHolder samlDocumentHolder = null;
   
   /**
    * Create an authentication request
    * @param id
    * @param assertionConsumerURL
    * @param destination
    * @param issuerValue
    * @return 
    * @throws ConfigurationException 
    */
   public AuthnRequestType createAuthnRequestType(String id, 
         String assertionConsumerURL, 
         String destination, 
         String issuerValue) throws ConfigurationException 
   {
      return JBossSAMLAuthnRequestFactory.createAuthnRequestType( 
            id, assertionConsumerURL, destination, issuerValue); 
   }
   
   /**
    * Get AuthnRequestType from a file
    * @param fileName file with the serialized AuthnRequestType
    * @return AuthnRequestType
    * @throws SAXException 
    * @throws JAXBException 
    * @throws IllegalArgumentException if the input fileName is null
    *         IllegalStateException if the InputStream from the fileName is null
    */
   public AuthnRequestType getAuthnRequestType(String fileName) throws JAXBException, SAXException 
   {   
      if(fileName == null)
         throw new IllegalArgumentException("fileName is null");
      ClassLoader tcl = SecurityActions.getContextClassLoader();
      InputStream is = tcl.getResourceAsStream(fileName);
      return getAuthnRequestType(is);
   } 
   
   /**
    * Get the Binder 
    * @return
    * @throws JAXBException
    */
   public Binder<Node> getBinder() throws JAXBException
   {
      JAXBContext jaxb = JAXBUtil.getJAXBContext(RequestAbstractType.class);
      return jaxb.createBinder();
   }
   
   /**
    * Get the Underlying SAML2Object from the input stream
    * @param is
    * @return
    * @throws IOException
    * @throws ParsingException
    */ 
   public SAML2Object getSAML2ObjectFromStream(InputStream is) 
   throws  ConfigurationException, ParsingException,
   ProcessingException
   {
      if(is == null)
         throw new IllegalStateException("InputStream is null"); 
      
      Document samlDocument =  DocumentUtil.getDocument(is); 
 
      /*try
      {*/
         /*Binder<Node> binder = getBinder();
         JAXBElement<SAML2Object> jaxbAuthnRequestType = (JAXBElement<SAML2Object>) binder.unmarshal(samlDocument);
         SAML2Object requestType = jaxbAuthnRequestType.getValue();*/
         
         SAMLParser samlParser = new SAMLParser();
         SAML2Object requestType = (SAML2Object) samlParser.parse( DocumentUtil.getNodeAsStream( samlDocument ));
         
         samlDocumentHolder = new SAMLDocumentHolder(requestType, samlDocument);
         return requestType;
      /*}
      catch (JAXBException e)
      {
         throw new ParsingException(e);
      }*/
   }
   
   /**
    * Get a Request Type from Input Stream
    * @param is
    * @return 
    * @throws ProcessingException 
    * @throws ConfigurationException 
    * @throws  
    * @throws IllegalArgumentException inputstream is null
    */
   @SuppressWarnings("unchecked")
   public RequestAbstractType getRequestType(InputStream is) 
   throws ParsingException, ConfigurationException, ProcessingException 
   {
      if(is == null)
         throw new IllegalStateException("InputStream is null"); 
      
      Document samlDocument = DocumentUtil.getDocument(is);
        
      try
      {
         Binder<Node> binder = getBinder();
         JAXBElement<RequestAbstractType> jaxbAuthnRequestType = (JAXBElement<RequestAbstractType>) binder.unmarshal(samlDocument);
         RequestAbstractType requestType = jaxbAuthnRequestType.getValue();
         samlDocumentHolder = new SAMLDocumentHolder(requestType, samlDocument);
         return requestType;
      }
      catch (JAXBException e)
      {
         throw new ParsingException(e);
      }
   }
   
   /**
    * Get the AuthnRequestType from an input stream
    * @param is Inputstream containing the AuthnRequest
    * @return
    * @throws SAXException 
    * @throws JAXBException 
    * @throws IllegalArgumentException inputstream is null
    */
   @SuppressWarnings("unchecked")
   public AuthnRequestType getAuthnRequestType(InputStream is) throws JAXBException, SAXException 
   {
      if(is == null)
         throw new IllegalStateException("InputStream is null");
      String key = PicketLinkFederationConstants.JAXB_SCHEMA_VALIDATION;
      boolean validate = Boolean.parseBoolean(SecurityActions.getSystemProperty(key, "false"));
      
      Unmarshaller un = JBossSAMLAuthnRequestFactory.getValidatingUnmarshaller(validate);
      JAXBElement<AuthnRequestType> jaxbAuthnRequestType = (JAXBElement<AuthnRequestType>) un.unmarshal(is);
      return jaxbAuthnRequestType.getValue();  
   } 
   

   /**
    * Get the parsed {@code SAMLDocumentHolder}
    * @return
    */
   public SAMLDocumentHolder getSamlDocumentHolder()
   {
      return samlDocumentHolder;
   }  
   
   /**
    * Create a Logout Request
    * @param issuer
    * @return  
    * @throws ConfigurationException 
    */
   public LogoutRequestType createLogoutRequest(String issuer) throws ConfigurationException 
   {
      org.picketlink.identity.federation.saml.v2.protocol.ObjectFactory of
             = new org.picketlink.identity.federation.saml.v2.protocol.ObjectFactory();
      LogoutRequestType lrt = of.createLogoutRequestType();
      lrt.setID(IDGenerator.create("ID_"));
      lrt.setIssueInstant(XMLTimeUtil.getIssueInstant());
      lrt.setVersion( JBossSAMLConstants.VERSION_2_0.get() ); 
      
      //Create an issuer 
      NameIDType issuerNameID = JBossSAMLBaseFactory.createNameID();
      issuerNameID.setValue(issuer);
      lrt.setIssuer(issuerNameID);
      
      return lrt;
   }
   
   /**
    * Parse an XACML Authorization Decision Query from an xml file
    * @param resourceName
    * @return
    * @throws JAXBException 
    */
   public XACMLAuthzDecisionQueryType parseXACMLDecisionQuery(String resourceName) throws JAXBException 
   {
      ClassLoader tcl = SecurityActions.getContextClassLoader();
      InputStream is = tcl.getResourceAsStream(resourceName);
      return this.parseXACMLDecisionQuery(is);
   }
   
   /**
    * XACMLAuthorizationDecisionQuery from an input stream
    * @param is The InputStream where the xacml query exists
    * @return
    * @throws JAXBException  
    */
   @SuppressWarnings("unchecked")
   public XACMLAuthzDecisionQueryType parseXACMLDecisionQuery(InputStream is) throws JAXBException 
   {
      if(is == null)
         throw new IllegalArgumentException("Inputstream is null");
      
      String samlPath = "org.picketlink.identity.federation.saml.v2.protocol";
      String xacmlPath = "org.jboss.security.xacml.core.model.context"; 
      String xsAssert = "org.picketlink.identity.federation.saml.v2.profiles.xacml.assertion";
      String xsProto = "org.picketlink.identity.federation.saml.v2.profiles.xacml.protocol";
      String path = samlPath + ":" + xacmlPath + ":" + xsAssert + ":" + xsProto;
      
      JAXBContext jaxb = JAXBUtil.getJAXBContext(path);
      Unmarshaller un = jaxb.createUnmarshaller();
      
      JAXBElement<RequestAbstractType> jaxbRequestType = (JAXBElement<RequestAbstractType>) un.unmarshal(is);
      RequestAbstractType req = jaxbRequestType.getValue();
      if(req instanceof XACMLAuthzDecisionQueryType == false)
         throw new IllegalStateException("Not of type XACMLAuthzDecisionQueryType");
      
      return (XACMLAuthzDecisionQueryType) req;
   }
   
   /**
    * Return the DOM object
    * @param rat
    * @return
    * @throws ProcessingException 
    * @throws ParsingException 
    * @throws ConfigurationException 
    */
   /*public Document convert(RequestAbstractType rat) 
   throws SAXException, IOException, JAXBException, ConfigurationException */
   
   public Document convert(RequestAbstractType rat) 
   throws ProcessingException, ConfigurationException, ParsingException 
   {
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      
      SAMLRequestWriter writer = new SAMLRequestWriter(StaxUtil.getXMLStreamWriter(bos));
      if( rat instanceof AuthnRequestType )
      {
         writer.write( (AuthnRequestType) rat);
      } 
      else if( rat instanceof LogoutRequestType )
      {
         writer.write( (LogoutRequestType) rat);
      }
      
      return DocumentUtil.getDocument( new String( bos.toByteArray() )); 
         
      /*JAXBContext jaxb = JAXBUtil.getJAXBContext(RequestAbstractType.class);
      Binder<Node> binder = jaxb.createBinder();
      
      Document doc = DocumentUtil.createDocument();
      binder.marshal(JAXBElementMappingUtil.get(rat), doc);
      return doc;*/ 
   }
   
   /**
    * Convert a SAML2 Response into a Document
    * @param responseType
    * @return
    * @throws JAXBException
    * @throws ParserConfigurationException
    */
   public Document convert(ResponseType responseType) throws JAXBException, ConfigurationException 
   {
      JAXBContext jaxb = JAXBUtil.getJAXBContext(ResponseType.class);
      Binder<Node> binder = jaxb.createBinder();
      
      Document doc = DocumentUtil.createDocument();
      binder.marshal(JAXBElementMappingUtil.get(responseType), doc);
      return doc; 
   }
   
   /**
    * Marshall the AuthnRequestType to an output stream
    * @param requestType
    * @param os
    * @throws JAXBException 
    * @throws SAXException 
    */
   public void marshall(RequestAbstractType requestType, OutputStream os) throws SAXException, JAXBException 
   {
      String key = PicketLinkFederationConstants.JAXB_SCHEMA_VALIDATION;
      boolean validate = Boolean.parseBoolean(SecurityActions.getSystemProperty(key, "false"));
      
      Marshaller marshaller = JBossSAMLAuthnRequestFactory.getValidatingMarshaller(validate);
      JAXBElement<?> j = JAXBElementMappingUtil.get(requestType);
      marshaller.marshal(j, os);
   }
   
   /**
    * Marshall the AuthnRequestType to a writer
    * @param requestType
    * @param writer
    * @throws JAXBException 
    * @throws SAXException 
    */
   public void marshall(RequestAbstractType requestType, Writer writer) throws SAXException, JAXBException 
   {
      String key = PicketLinkFederationConstants.JAXB_SCHEMA_VALIDATION;
      boolean validate = Boolean.parseBoolean(SecurityActions.getSystemProperty(key, "false"));
      
      Marshaller marshaller = JBossSAMLAuthnRequestFactory.getValidatingMarshaller(validate);
      JAXBElement<?> j = JAXBElementMappingUtil.get(requestType);
      marshaller.marshal(j, writer);
   }
}