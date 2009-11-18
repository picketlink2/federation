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
package org.picketlink.identity.federation.core.saml.md.providers;

import java.util.List;

import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLConstants;
import org.picketlink.identity.federation.core.util.JAXBUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeType;
import org.picketlink.identity.federation.saml.v2.metadata.EndpointType;
import org.picketlink.identity.federation.saml.v2.metadata.EntityDescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.IDPSSODescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.KeyDescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.LocalizedNameType;
import org.picketlink.identity.federation.saml.v2.metadata.LocalizedURIType;
import org.picketlink.identity.federation.saml.v2.metadata.ObjectFactory;
import org.picketlink.identity.federation.saml.v2.metadata.OrganizationType;
import org.picketlink.identity.federation.saml.v2.metadata.SPSSODescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.SSODescriptorType;

/**
 * SAML2 Metadata Builder API
 * @author Anil.Saldhana@redhat.com
 * @since Apr 19, 2009
 */
public class MetaDataBuilderDelegate
{
   private static ObjectFactory oFact = new ObjectFactory();
   
   private static String pkgName = "org.picketlink.identity.federation.saml.v2.metadata";
   /**
    * Create an Endpoint (SingleSignOnEndpoint or SingleLogoutEndpoint)
    * @param binding
    * @param location
    * @param responseLocation
    * @return
    */
   public static EndpointType createEndpoint(String binding, String location,
         String responseLocation)
   {
      EndpointType endpoint = oFact.createEndpointType();
      endpoint.setBinding(binding);
      endpoint.setLocation(location);
      endpoint.setResponseLocation(responseLocation);
      return endpoint;
   }
   
   /**
    * Create an Organization
    * @param organizationName
    * @param organizationDisplayName
    * @param organizationURL
    * @param lang
    * @return
    */
   public static OrganizationType createOrganization(String organizationName,
         String organizationDisplayName, String organizationURL, String lang)
   {
      if(organizationName == null)
         throw new IllegalArgumentException("organizationName is null");
      if(organizationDisplayName == null)
         throw new IllegalArgumentException("organizationDisplayName is null");
      if(organizationURL == null)
         throw new IllegalArgumentException("organizationURL is null");
      if(lang == null)
         lang = JBossSAMLConstants.LANG_EN.get();
      
      //orgName
      LocalizedNameType orgName = oFact.createLocalizedNameType();
      orgName.setValue(organizationName);
      orgName.setLang(lang);
      
      //orgDisplayName
      LocalizedNameType orgDisplayName = oFact.createLocalizedNameType();
      orgDisplayName.setValue(organizationDisplayName);
      orgDisplayName.setLang(lang);
      
      //orgURL
      LocalizedURIType orgURL = oFact.createLocalizedURIType();
      orgURL.setValue(organizationURL);
      orgURL.setLang(lang);
      
      OrganizationType orgType = oFact.createOrganizationType();
      orgType.getOrganizationName().add(orgName);
      orgType.getOrganizationDisplayName().add(orgDisplayName);
      orgType.getOrganizationURL().add(orgURL);
      return orgType;
   }
   
   /**
    * Create an Entity Descriptor
    * @param idpOrSPDescriptor a descriptor for either the IDP or SSO
    * @return
    */
   public static EntityDescriptorType createEntityDescriptor(SSODescriptorType idpOrSPDescriptor)
   {
      EntityDescriptorType entity = oFact.createEntityDescriptorType();
      entity.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor().add(idpOrSPDescriptor); 
      return entity; 
   }
   
   /**
    * Create a IDP SSO metadata descriptor
    * @param requestsSigned
    * @param keyDescriptorType
    * @param ssoEndPoint
    * @param sloEndPoint
    * @param attributes
    * @param org
    * @return
    */
   public static IDPSSODescriptorType createIDPSSODescriptor(boolean requestsSigned, 
         KeyDescriptorType keyDescriptorType, 
         EndpointType ssoEndPoint, 
         EndpointType sloEndPoint,
         List<AttributeType> attributes,
         OrganizationType org)
   {
      IDPSSODescriptorType idp = oFact.createIDPSSODescriptorType();
      idp.getSingleSignOnService().add(ssoEndPoint);
      idp.getSingleLogoutService().add(sloEndPoint);
      idp.getAttribute().addAll(attributes);
      idp.getKeyDescriptor().add(keyDescriptorType);
      idp.setWantAuthnRequestsSigned(requestsSigned);
      idp.setOrganization(org);
      return idp;
   }
   
   /**
    * Create a IDP SSO metadata descriptor
    * @param requestsSigned
    * @param keyDescriptorType
    * @param ssoEndPoint
    * @param sloEndPoint
    * @param attributes
    * @param org
    * @return
    */
   public static SPSSODescriptorType createSPSSODescriptor(boolean requestsSigned, 
         KeyDescriptorType keyDescriptorType,  
         EndpointType sloEndPoint,
         List<AttributeType> attributes,
         OrganizationType org)
   {
      SPSSODescriptorType sp = oFact.createSPSSODescriptorType();
      sp.getSingleLogoutService().add(sloEndPoint);
      sp.getKeyDescriptor().add(keyDescriptorType);
      sp.setAuthnRequestsSigned(requestsSigned); 
      sp.setOrganization(org);
      return sp;
   }
   
   /**
    * Get the marshaller
    * @return 
    * @throws JAXBException 
    */
   public static Marshaller getMarshaller() throws JAXBException
   {
      return JAXBUtil.getMarshaller(pkgName);
   }
   
   /**
    * Get the Unmarshaller
    * @return 
    * @throws JAXBException 
    */
   public static Unmarshaller getUnmarshaller() throws JAXBException  
   {
      return JAXBUtil.getUnmarshaller(pkgName);
   }
   
   /**
    * Get the ObjectFactory for method chaining
    * @return
    */
   public static ObjectFactory getObjectFactory()
   {
      return oFact;
   }
}