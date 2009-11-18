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
package org.jboss.identity.federation.core.util;

import java.security.PublicKey;

import org.apache.log4j.Logger;
import org.jboss.identity.federation.core.config.KeyProviderType;
import org.jboss.identity.federation.core.config.ProviderType;
import org.jboss.identity.federation.core.exceptions.ConfigurationException;
import org.jboss.identity.federation.core.exceptions.ProcessingException;
import org.jboss.identity.federation.core.interfaces.TrustKeyManager;

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
         ClassLoader tcl = SecurityActions.getContextClassLoader();
         String keyManagerClassName = keyProvider.getClassName();
         if(keyManagerClassName == null)
            throw new RuntimeException("KeyManager class name is null");

         Class<?> clazz = tcl.loadClass(keyManagerClassName);
         trustKeyManager = (TrustKeyManager) clazz.newInstance();
      }
      catch(Exception e)
      {
         log.error("Exception in getting TrustKeyManager:",e); 
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
   public static PublicKey getValidatingKey(TrustKeyManager trustKeyManager, 
         String domain)
   throws ConfigurationException, ProcessingException
   {   
      if(trustKeyManager == null)
         throw new IllegalArgumentException("Trust Key Manager is null");
      
      return trustKeyManager.getValidatingKey(domain); 
   } 
}