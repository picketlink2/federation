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
package org.picketlink.identity.federation.core.util;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.log4j.Logger;
import org.picketlink.identity.federation.core.config.AuthPropertyType;
import org.picketlink.identity.federation.core.config.ClaimsProcessorType;
import org.picketlink.identity.federation.core.config.KeyProviderType;
import org.picketlink.identity.federation.core.config.KeyValueType;
import org.picketlink.identity.federation.core.config.ProviderType;
import org.picketlink.identity.federation.core.config.SPType;
import org.picketlink.identity.federation.core.config.TokenProviderType;
import org.picketlink.identity.federation.core.constants.PicketLinkFederationConstants;
import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.interfaces.TrustKeyManager;
import org.picketlink.identity.federation.saml.v2.metadata.EndpointType;
import org.picketlink.identity.federation.saml.v2.metadata.EntityDescriptorType;
import org.picketlink.identity.federation.saml.v2.metadata.EntityDescriptorType.EDTChoiceType;
import org.picketlink.identity.federation.saml.v2.metadata.EntityDescriptorType.EDTDescriptorChoiceType;
import org.picketlink.identity.federation.saml.v2.metadata.IDPSSODescriptorType;

/**
 * Utility for configuration
 * @author Anil.Saldhana@redhat.com
 * @since Nov 13, 2009
 */
public class CoreConfigUtil
{
   private static Logger log = Logger.getLogger(CoreConfigUtil.class);

   /**
    * Given either the IDP Configuration or the SP Configuration, derive
    * the TrustKeyManager
    * @param idpOrSPConfiguration
    * @return
    */
   public static TrustKeyManager getTrustKeyManager(ProviderType idpOrSPConfiguration)
   {
      KeyProviderType keyProvider = idpOrSPConfiguration.getKeyProvider();
      return getTrustKeyManager(keyProvider);
   }

   /**
    * Once the {@code KeyProviderType} is derived, get
    * the {@code TrustKeyManager}
    * @param keyProvider
    * @return
    */
   public static TrustKeyManager getTrustKeyManager(KeyProviderType keyProvider)
   {
      TrustKeyManager trustKeyManager = null;
      try
      {
         String keyManagerClassName = keyProvider.getClassName();
         if (keyManagerClassName == null)
            throw new RuntimeException("KeyManager class name is null");

         Class<?> clazz = SecurityActions.loadClass(CoreConfigUtil.class, keyManagerClassName);
         if (clazz == null)
            throw new RuntimeException(keyManagerClassName + " could not be loaded");
         trustKeyManager = (TrustKeyManager) clazz.newInstance();
      }
      catch (Exception e)
      {
         log.error("Exception in getting TrustKeyManager:", e);
      }
      return trustKeyManager;
   }

   /**
    * Get the validating key
    * @param idpSpConfiguration
    * @param domain
    * @return
    * @throws ConfigurationException
    * @throws ProcessingException
    */
   public static PublicKey getValidatingKey(ProviderType idpSpConfiguration, String domain)
         throws ConfigurationException, ProcessingException
   {
      TrustKeyManager trustKeyManager = getTrustKeyManager(idpSpConfiguration);

      return getValidatingKey(trustKeyManager, domain);
   }

   /**
    * Get the validating key given the trust key manager
    * @param trustKeyManager
    * @param domain
    * @return
    * @throws ConfigurationException
    * @throws ProcessingException
    */
   public static PublicKey getValidatingKey(TrustKeyManager trustKeyManager, String domain)
         throws ConfigurationException, ProcessingException
   {
      if (trustKeyManager == null)
         throw new IllegalArgumentException("Trust Key Manager is null");

      return trustKeyManager.getValidatingKey(domain);
   }

   /**
    * Given a {@code KeyProviderType}, return the list of auth properties that have been decrypted for any
    * masked password
    * @param keyProviderType
    * @return
    * @throws GeneralSecurityException
    */
   @SuppressWarnings("unchecked")
   public static List<AuthPropertyType> getKeyProviderProperties(KeyProviderType keyProviderType)
         throws GeneralSecurityException
   {
      List<AuthPropertyType> authProperties = keyProviderType.getAuth();
      if (decryptionNeeded(authProperties))
         authProperties = decryptPasswords(authProperties);

      return authProperties;
   }

   /**
    * Given a {@code TokenProviderType}, return the list of properties that have been decrypted for
    * any masked property value
    * @param tokenProviderType
    * @return
    * @throws GeneralSecurityException
    */
   @SuppressWarnings("unchecked")
   public static List<KeyValueType> getProperties(TokenProviderType tokenProviderType) throws GeneralSecurityException
   {
      List<KeyValueType> keyValueTypeList = tokenProviderType.getProperty();
      if (decryptionNeeded(keyValueTypeList))
         keyValueTypeList = decryptPasswords(keyValueTypeList);

      return keyValueTypeList;
   }

   /**
    * Given a {@code ClaimsProcessorType}, return the list of properties that have been decrypted for
    * any masked property value
    * @param claimsProcessorType
    * @return
    * @throws GeneralSecurityException
    */
   @SuppressWarnings("unchecked")
   public static List<KeyValueType> getProperties(ClaimsProcessorType claimsProcessorType)
         throws GeneralSecurityException
   {
      List<KeyValueType> keyValueTypeList = claimsProcessorType.getProperty();
      if (decryptionNeeded(keyValueTypeList))
         keyValueTypeList = decryptPasswords(keyValueTypeList);

      return keyValueTypeList;
   }

   /**
    * Given a key value list, check if decrypt of any properties is needed. 
    * Unless one of the keys is "salt", we cannot figure out is decrypt is needed
    * @param keyValueList
    * @return
    */
   public static boolean decryptionNeeded(List<? extends KeyValueType> keyValueList)
   {
      int length = keyValueList.size();

      //Let us run through the list to see if there is any salt
      for (int i = 0; i < length; i++)
      {
         KeyValueType kvt = keyValueList.get(i);

         String key = kvt.getKey();
         if (PicketLinkFederationConstants.SALT.equalsIgnoreCase(key))
            return true;
      }
      return false;
   }

   /**
    * Given a key value pair read from PicketLink configuration, ensure
    * that we replace the masked passwords with the decoded passwords
    * and pass it back
    * 
    * @param keyValueList
    * @return
    * @throws GeneralSecurityException 
    * @throws Exception
    */
   @SuppressWarnings("rawtypes")
   private static List decryptPasswords(List keyValueList) throws GeneralSecurityException
   {
      String pbeAlgo = PicketLinkFederationConstants.PBE_ALGORITHM;

      String salt = null;
      int iterationCount = 0;

      int length = keyValueList.size();

      //Let us run through the list to see if there is any salt
      for (int i = 0; i < length; i++)
      {
         KeyValueType kvt = (KeyValueType) keyValueList.get(i);

         String key = kvt.getKey();
         if (PicketLinkFederationConstants.SALT.equalsIgnoreCase(key))
            salt = kvt.getValue();
         if (PicketLinkFederationConstants.ITERATION_COUNT.equalsIgnoreCase(key))
            iterationCount = Integer.parseInt(kvt.getValue());
      }

      if (salt == null)
         return keyValueList;

      //Ok. there is a salt configured. So we have some properties with masked values
      List<KeyValueType> returningList = new ArrayList<KeyValueType>();

      // Create the PBE secret key 
      SecretKeyFactory factory = SecretKeyFactory.getInstance(pbeAlgo);

      char[] password = "somearbitrarycrazystringthatdoesnotmatter".toCharArray();
      PBEParameterSpec cipherSpec = new PBEParameterSpec(salt.getBytes(), iterationCount);
      PBEKeySpec keySpec = new PBEKeySpec(password);
      SecretKey cipherKey = factory.generateSecret(keySpec);

      for (int i = 0; i < length; i++)
      {
         KeyValueType kvt = (KeyValueType) keyValueList.get(i);

         String val = kvt.getValue();
         if (val.startsWith(PicketLinkFederationConstants.PASS_MASK_PREFIX))
         {
            val = val.substring(PicketLinkFederationConstants.PASS_MASK_PREFIX.length());
            String decodedValue;
            try
            {
               decodedValue = PBEUtils.decode64(val, pbeAlgo, cipherKey, cipherSpec);
            }
            catch (UnsupportedEncodingException e)
            {
               throw new RuntimeException(e);
            }

            KeyValueType newKVT = new KeyValueType();
            if (keyValueList.get(0) instanceof AuthPropertyType)
               newKVT = new AuthPropertyType();
            newKVT.setKey(kvt.getKey());
            newKVT.setValue(new String(decodedValue));
            returningList.add(newKVT);
         }
         else
         {
            returningList.add(kvt);
         }
      }

      return returningList;
   }

   public static SPType getSPConfiguration(EntityDescriptorType entityDescriptor, String bindingURI)
   {
      List<EDTChoiceType> edtChoices = entityDescriptor.getChoiceType();
      for (EDTChoiceType edt : edtChoices)
      {
         List<EDTDescriptorChoiceType> edtDescriptors = edt.getDescriptors();
         for (EDTDescriptorChoiceType edtDesc : edtDescriptors)
         {
            IDPSSODescriptorType idpSSO = edtDesc.getIdpDescriptor();
            if (idpSSO != null)
            {
               return getSPConfiguration(idpSSO, bindingURI);
            }
         }
      }
      return null;
   }

   public static IDPSSODescriptorType getIDPDescriptor(EntityDescriptorType entityDescriptor)
   {
      List<EDTChoiceType> edtChoices = entityDescriptor.getChoiceType();
      for (EDTChoiceType edt : edtChoices)
      {
         List<EDTDescriptorChoiceType> edtDescriptors = edt.getDescriptors();
         for (EDTDescriptorChoiceType edtDesc : edtDescriptors)
         {
            IDPSSODescriptorType idpSSO = edtDesc.getIdpDescriptor();
            if (idpSSO != null)
            {
               return idpSSO;
            }
         }
      }
      return null;
   }

   public static SPType getSPConfiguration(IDPSSODescriptorType idp, String bindingURI)
   {
      String identityURL = null;

      SPType sp = new SPType();
      List<EndpointType> endpoints = idp.getSingleSignOnService();
      for (EndpointType endpoint : endpoints)
      {
         if (endpoint.getBinding().toString().equals(bindingURI))
         {
            identityURL = endpoint.getLocation().toString();
            break;
         }

      }
      //get identity url
      sp.setIdentityURL(identityURL);
      return sp;
   }
}