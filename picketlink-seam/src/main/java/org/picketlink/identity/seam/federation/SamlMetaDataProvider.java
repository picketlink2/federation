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
package org.picketlink.identity.seam.federation;

import java.io.OutputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.jboss.seam.annotations.AutoCreate;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Name;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.saml.v2.metadata.EntityDescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.IndexedEndpointType;
import org.picketlink.identity.federation.saml.v2.metadata.KeyDescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.KeyTypes;
import org.picketlink.identity.federation.saml.v2.metadata.ObjectFactory;
import org.picketlink.identity.federation.saml.v2.metadata.SPSSODescriptorType;
import org.picketlink.identity.seam.federation.configuration.ServiceProvider;
import org.picketlink.identity.xmlsec.w3.xmldsig.KeyInfoType;
import org.picketlink.identity.xmlsec.w3.xmldsig.X509DataType;

/**
* @author Marcel Kolsteren
* @since Jan 20, 2010
*/
@Name("org.picketlink.identity.seam.federation.samlMetaDataProvider")
@AutoCreate
public class SamlMetaDataProvider
{
   @In
   private ServiceProvider serviceProvider;

   public void writeMetaData(OutputStream stream)
   {
      try
      {
         ObjectFactory metaDataFactory = new ObjectFactory();

         IndexedEndpointType acsRedirectEndpoint = metaDataFactory.createIndexedEndpointType();
         acsRedirectEndpoint.setBinding(SamlConstants.HTTP_REDIRECT_BINDING);
         acsRedirectEndpoint.setLocation(serviceProvider
               .getServiceURL(ExternalAuthenticationService.SAML_ASSERTION_CONSUMER_SERVICE));

         IndexedEndpointType acsPostEndpoint = metaDataFactory.createIndexedEndpointType();
         acsPostEndpoint.setBinding(SamlConstants.HTTP_POST_BINDING);
         acsPostEndpoint.setLocation(serviceProvider
               .getServiceURL(ExternalAuthenticationService.SAML_ASSERTION_CONSUMER_SERVICE));

         IndexedEndpointType sloRedirectEndpoint = metaDataFactory.createIndexedEndpointType();
         sloRedirectEndpoint.setBinding(SamlConstants.HTTP_REDIRECT_BINDING);
         sloRedirectEndpoint.setLocation(serviceProvider
               .getServiceURL(ExternalAuthenticationService.SAML_SINGLE_LOGOUT_SERVICE));

         IndexedEndpointType sloPostEndpoint = metaDataFactory.createIndexedEndpointType();
         sloPostEndpoint.setBinding(SamlConstants.HTTP_POST_BINDING);
         sloPostEndpoint.setLocation(serviceProvider
               .getServiceURL(ExternalAuthenticationService.SAML_SINGLE_LOGOUT_SERVICE));

         SPSSODescriptorType spSsoDescriptor = metaDataFactory.createSPSSODescriptorType();
         spSsoDescriptor.setAuthnRequestsSigned(serviceProvider.getSamlConfiguration().isAuthnRequestsSigned());
         spSsoDescriptor.setWantAssertionsSigned(serviceProvider.getSamlConfiguration().isWantAssertionsSigned());

         spSsoDescriptor.getAssertionConsumerService().add(acsRedirectEndpoint);
         spSsoDescriptor.getAssertionConsumerService().add(acsPostEndpoint);
         spSsoDescriptor.getSingleLogoutService().add(sloRedirectEndpoint);
         spSsoDescriptor.getSingleLogoutService().add(sloPostEndpoint);

         spSsoDescriptor.getProtocolSupportEnumeration().add(JBossSAMLURIConstants.PROTOCOL_NSURI.get());

         spSsoDescriptor.getNameIDFormat().add("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
         spSsoDescriptor.getNameIDFormat().add("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
         spSsoDescriptor.getNameIDFormat().add("urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified");
         spSsoDescriptor.getNameIDFormat().add("urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress");

         org.picketlink.identity.xmlsec.w3.xmldsig.ObjectFactory signatureFactory = new org.picketlink.identity.xmlsec.w3.xmldsig.ObjectFactory();

         X509Certificate certificate = serviceProvider.getSamlConfiguration().getCertificate();

         JAXBElement<byte[]> X509Certificate;
         try
         {
            X509Certificate = signatureFactory.createX509DataTypeX509Certificate(certificate.getEncoded());
         }
         catch (CertificateEncodingException e)
         {
            throw new RuntimeException(e);
         }

         X509DataType X509Data = signatureFactory.createX509DataType();
         X509Data.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(X509Certificate);

         KeyInfoType keyInfo = signatureFactory.createKeyInfoType();
         keyInfo.getContent().add(signatureFactory.createX509Data(X509Data));

         KeyDescriptorType keyDescriptor = metaDataFactory.createKeyDescriptorType();
         keyDescriptor.setUse(KeyTypes.SIGNING);
         keyDescriptor.setKeyInfo(keyInfo);

         spSsoDescriptor.getKeyDescriptor().add(keyDescriptor);

         EntityDescriptorType entityDescriptor = metaDataFactory.createEntityDescriptorType();
         entityDescriptor.setEntityID(serviceProvider.getSamlConfiguration().getEntityId());
         entityDescriptor.getRoleDescriptorOrIDPSSODescriptorOrSPSSODescriptor().add(spSsoDescriptor);

         JAXBContext jaxbContext = JAXBContext.newInstance("org.picketlink.identity.federation.saml.v2.metadata");
         Marshaller marshaller = jaxbContext.createMarshaller();
         marshaller.setProperty(Marshaller.JAXB_ENCODING, "UTF-8");
         marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
         marshaller.marshal(metaDataFactory.createEntityDescriptor(entityDescriptor), stream);
      }
      catch (JAXBException e)
      {
         throw new RuntimeException(e);
      }
   }
}
