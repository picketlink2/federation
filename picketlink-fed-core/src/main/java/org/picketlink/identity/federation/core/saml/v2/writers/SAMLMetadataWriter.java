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

import static org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants.METADATA_NSURI;

import java.net.URI;
import java.util.List;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamWriter;

import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLConstants;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.core.util.StaxUtil;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AttributeType;
import org.picketlink.identity.federation.newmodel.saml.v2.metadata.AffiliationDescriptorType;
import org.picketlink.identity.federation.newmodel.saml.v2.metadata.AttributeAuthorityDescriptorType;
import org.picketlink.identity.federation.newmodel.saml.v2.metadata.AuthnAuthorityDescriptorType;
import org.picketlink.identity.federation.newmodel.saml.v2.metadata.EndpointType;
import org.picketlink.identity.federation.newmodel.saml.v2.metadata.EntityDescriptorType;
import org.picketlink.identity.federation.newmodel.saml.v2.metadata.EntityDescriptorType.EDTChoiceType;
import org.picketlink.identity.federation.newmodel.saml.v2.metadata.EntityDescriptorType.EDTDescriptorChoiceType;
import org.picketlink.identity.federation.newmodel.saml.v2.metadata.IDPSSODescriptorType;
import org.picketlink.identity.federation.newmodel.saml.v2.metadata.IndexedEndpointType;
import org.picketlink.identity.federation.newmodel.saml.v2.metadata.KeyDescriptorType;
import org.picketlink.identity.federation.newmodel.saml.v2.metadata.LocalizedNameType;
import org.picketlink.identity.federation.newmodel.saml.v2.metadata.LocalizedURIType;
import org.picketlink.identity.federation.newmodel.saml.v2.metadata.OrganizationType;
import org.picketlink.identity.federation.newmodel.saml.v2.metadata.SPSSODescriptorType;
import org.picketlink.identity.federation.newmodel.saml.v2.metadata.SSODescriptorType;
import org.w3c.dom.Element;

/**
 * Write the SAML metadata elements
 * @author Anil.Saldhana@redhat.com
 * @since Dec 14, 2010
 */
public class SAMLMetadataWriter extends BaseWriter
{
   private String METADATA_PREFIX = "md";

   public SAMLMetadataWriter(XMLStreamWriter writer) throws ProcessingException
   {
      super(writer); 
   }
   
   public void writeEntityDescriptor( EntityDescriptorType entityDescriptor ) throws ProcessingException
   {
      StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.ENTITY_DESCRIPTOR.get(), METADATA_NSURI.get());
      StaxUtil.writeDefaultNameSpace(writer, JBossSAMLURIConstants.METADATA_NSURI.get() );
      StaxUtil.writeNameSpace(writer, "md", JBossSAMLURIConstants.METADATA_NSURI.get() ); 
      StaxUtil.writeNameSpace(writer, "saml", JBossSAMLURIConstants.ASSERTION_NSURI.get() ); 
      StaxUtil.writeNameSpace(writer, "ds", JBossSAMLURIConstants.XMLDSIG_NSURI.get() ); 
      
      StaxUtil.writeAttribute(writer, JBossSAMLConstants.ENTITY_ID.get(), entityDescriptor.getEntityID() );
      
      List<EDTChoiceType> choiceTypes = entityDescriptor.getChoiceType();
      for( EDTChoiceType edtChoice : choiceTypes )
      {
         AffiliationDescriptorType affliationDesc = edtChoice.getAffiliationDescriptor();
         if( affliationDesc != null )
            throw new RuntimeException( "handle affliation" ); //TODO: affiliation
         
         List<EDTDescriptorChoiceType> edtDescChoices = edtChoice.getDescriptors();
         for( EDTDescriptorChoiceType edtDescChoice : edtDescChoices )
         {
            IDPSSODescriptorType idpSSO = edtDescChoice.getIdpDescriptor();
            if( idpSSO != null )
               write( edtDescChoice.getIdpDescriptor() ); 
            
            SPSSODescriptorType spSSO = edtDescChoice.getSpDescriptor();
            if( spSSO != null )
               throw new RuntimeException( "NYI" );
            
            AttributeAuthorityDescriptorType attribAuth = edtDescChoice.getAttribDescriptor();
            if( attribAuth != null )
               writeAttributeAuthorityDescriptor(attribAuth);
            
            AuthnAuthorityDescriptorType authNDesc = edtDescChoice.getAuthnDescriptor();
            if( authNDesc != null )
               throw new RuntimeException( "NYI" );
         }
      }
      
      StaxUtil.writeEndElement(writer);
      StaxUtil.flush(writer); 
   }
   
   public void write( SSODescriptorType ssoDescriptor ) throws ProcessingException
   {
      throw new RuntimeException( "should not called" );
   }
   public void write( SPSSODescriptorType spSSODescriptor ) throws ProcessingException
   {
      throw new RuntimeException( "NYI" );
   }
   
   public void write( IDPSSODescriptorType idpSSODescriptor ) throws ProcessingException
   {
      StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.IDP_SSO_DESCRIPTOR.get(), METADATA_NSURI.get());
      
      boolean wantsAuthnRequestsSigned = idpSSODescriptor.isWantAuthnRequestsSigned();
      StaxUtil.writeAttribute(writer, new QName( JBossSAMLConstants.WANT_AUTHN_REQUESTS_SIGNED.get() ), "" + wantsAuthnRequestsSigned );
      
      writeProtocolSupportEnumeration( idpSSODescriptor.getProtocolSupportEnumeration() );
      
      List<IndexedEndpointType> artifactResolutionServices = idpSSODescriptor.getArtifactResolutionService();
      for( IndexedEndpointType indexedEndpoint: artifactResolutionServices )
      {
         writeArtifactResolutionService( indexedEndpoint );
      }
      
      List<EndpointType> sloServices = idpSSODescriptor.getSingleLogoutService();
      for( EndpointType endpoint: sloServices )
      {
         writeSingleLogoutService(endpoint);
      }
      
      List<EndpointType> ssoServices = idpSSODescriptor.getSingleSignOnService();
      for( EndpointType endpoint: ssoServices )
      {
         writeSingleSignOnService( endpoint );
      }
      
      List<String> nameIDFormats = idpSSODescriptor.getNameIDFormat();
      for( String nameIDFormat: nameIDFormats )
      {
         writeNameIDFormat( nameIDFormat );
      }
      
      List<AttributeType> attributes = idpSSODescriptor.getAttribute();
      for( AttributeType attribType : attributes )
      {
         write( attribType );
      }
      
      StaxUtil.writeEndElement(writer);
      StaxUtil.flush(writer);  
   }
   
   public void writeAttributeAuthorityDescriptor( AttributeAuthorityDescriptorType attributeAuthority ) throws ProcessingException
   { 
      StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.ATTRIBUTE_AUTHORITY_DESCRIPTOR.get(),
            METADATA_NSURI.get());
      
      writeProtocolSupportEnumeration( attributeAuthority.getProtocolSupportEnumeration() );
      
      List<KeyDescriptorType> keyDescriptorList = attributeAuthority.getKeyDescriptor();
      for( KeyDescriptorType keyDescriptor: keyDescriptorList )
      {
         writeKeyDescriptor( keyDescriptor );
      }
      
      List<EndpointType> attributeServices = attributeAuthority.getAttributeService();
      for( EndpointType endpoint : attributeServices )
      {
         writeAttributeService( endpoint );
      }
      
      List<String> nameIDFormats = attributeAuthority.getNameIDFormat();
      for( String nameIDFormat: nameIDFormats )
      { 
         writeNameIDFormat( nameIDFormat );
      }
      
      List<AttributeType> attributes = attributeAuthority.getAttribute();
      for( AttributeType attributeType: attributes )
      {
         write( attributeType );
      }
      StaxUtil.writeEndElement(writer);
      StaxUtil.flush(writer);   
   }
   
   public void writeArtifactResolutionService( IndexedEndpointType indexedEndpoint ) throws ProcessingException
   {
      StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.ARTIFACT_RESOLUTION_SERVICE.get(), METADATA_NSURI.get());

      writeEndpointType( indexedEndpoint ); 
      
      StaxUtil.writeAttribute(writer, JBossSAMLConstants.ISDEFAULT.get(), ""+ indexedEndpoint.isIsDefault() );
      StaxUtil.writeAttribute(writer, JBossSAMLConstants.INDEX.get(), ""+ indexedEndpoint.getIndex() );
      
      StaxUtil.writeEndElement(writer);
      StaxUtil.flush(writer);   
   }
   
   public void writeOrganization( OrganizationType org ) throws ProcessingException
   { 
      StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.ORGANIZATION.get(),
            METADATA_NSURI.get());
      
      //Write the name
      List<LocalizedNameType> nameList = org.getOrganizationName();
      for( LocalizedNameType localName: nameList )
      {
         StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.ORGANIZATION_NAME.get(),
               METADATA_NSURI.get());
         
         writeLocalizedType( localName ); 
      }
      
      //Write the display name
      List<LocalizedNameType> displayNameList = org.getOrganizationDisplayName();
      for( LocalizedNameType localName: displayNameList )
      {
         StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.ORGANIZATION_DISPLAY_NAME.get(),
               METADATA_NSURI.get());
         writeLocalizedType( localName ); 
      }
      
      //Write the url
      List<LocalizedURIType> uriList = org.getOrganizationURL();
      for( LocalizedURIType uri: uriList )
      {
         StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.ORGANIZATION_URL.get(),
               METADATA_NSURI.get());
         
         String lang = uri.getLang();
         String val = uri.getValue().toString();
         StaxUtil.writeAttribute(writer, new QName( JBossSAMLURIConstants.XML.get(), JBossSAMLConstants.LANG.get(), "xml" ), lang );
         
         StaxUtil.writeCharacters(writer, val );
         
         StaxUtil.writeEndElement(writer);
      }

      StaxUtil.writeEndElement(writer);
      StaxUtil.flush(writer);
   }
   
   public void writeKeyDescriptor( KeyDescriptorType keyDescriptor ) throws ProcessingException
   { 
      StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.KEY_DESCRIPTOR.get(),
            METADATA_NSURI.get());
      
      Element keyInfo = keyDescriptor.getKeyInfo();
      StaxUtil.writeDOMElement(writer, keyInfo);
      StaxUtil.writeEndElement(writer);
      StaxUtil.flush(writer);
   }
   
   public void writeAttributeService( EndpointType endpoint ) throws ProcessingException
   {
      StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.ATTRIBUTE_SERVICE.get(), METADATA_NSURI.get());
      
      writeEndpointType( endpoint );
      
      StaxUtil.writeEndElement(writer);
      StaxUtil.flush(writer);
   }
   
   public void writeSingleLogoutService( EndpointType endpoint ) throws ProcessingException
   {
     StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.SINGLE_LOGOUT_SERVICE.get(), METADATA_NSURI.get());
      
      writeEndpointType( endpoint );
      
      StaxUtil.writeEndElement(writer);
      StaxUtil.flush(writer);
   }
   
   public void writeSingleSignOnService( EndpointType endpoint ) throws ProcessingException
   {
     StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.SINGLE_SIGNON_SERVICE.get(), METADATA_NSURI.get());
      
      writeEndpointType( endpoint );
      
      StaxUtil.writeEndElement(writer);
      StaxUtil.flush(writer);
   }
   
   private void writeProtocolSupportEnumeration( List<String> protoEnum ) throws ProcessingException
   {
      if( protoEnum.size() > 0 )
      {
         StringBuilder sb = new StringBuilder();
         for( String str: protoEnum )
         {
            sb.append(str).append(" ");
         }
         
         StaxUtil.writeAttribute(writer, new QName( JBossSAMLConstants.PROTOCOL_SUPPORT_ENUMERATION.get() ), sb.toString().trim() ); 
      }
   }
   
   private void writeEndpointType( EndpointType endpoint ) throws ProcessingException
   {
      StaxUtil.writeAttribute(writer, JBossSAMLConstants.BINDING.get(), endpoint.getBinding().toString() );
      StaxUtil.writeAttribute(writer, JBossSAMLConstants.LOCATION.get(), endpoint.getLocation().toString() );
      
      URI responseLocation = endpoint.getResponseLocation();
      if( responseLocation != null )
      {
         StaxUtil.writeAttribute(writer, JBossSAMLConstants.RESPONSE_LOCATION.get(), responseLocation.toString() );
      }
   }
   
   private void writeLocalizedType( LocalizedNameType localName ) throws ProcessingException
   {
      String lang = localName.getLang();
      String val = localName.getValue();
      StaxUtil.writeAttribute(writer, new QName( JBossSAMLURIConstants.XML.get(), JBossSAMLConstants.LANG.get(), "xml" ), lang );
      
      StaxUtil.writeCharacters(writer, val );
      
      StaxUtil.writeEndElement(writer);
   }
   
   private void writeNameIDFormat( String nameIDFormat ) throws ProcessingException
   {
      StaxUtil.writeStartElement(writer, METADATA_PREFIX, JBossSAMLConstants.NAMEID_FORMAT.get(), METADATA_NSURI.get());

      StaxUtil.writeCharacters(writer, nameIDFormat );
      StaxUtil.writeEndElement(writer);
   }
}