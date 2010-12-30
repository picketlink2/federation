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
package org.picketlink.identity.federation.core.sts;

import java.util.List;

import javax.xml.namespace.QName;

import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.interfaces.ProtocolContext;
import org.picketlink.identity.federation.core.interfaces.SecurityTokenProvider;
import org.picketlink.identity.federation.core.saml.v2.providers.SAML20AssertionTokenProvider;
import org.picketlink.identity.federation.core.wstrust.PicketLinkSTSConfiguration;

/**
 * <p>
 * Generic STS Core.
 * </p>
 * <p>
 * This is a Singleton Class.
 * </p>
 * @see {@code #instance()}
 * 
 * @author Anil.Saldhana@redhat.com
 * @since Dec 27, 2010
 */
public class PicketLinkCoreSTS
{
   public static final RuntimePermission rte = new RuntimePermission( "org.picketlink.sts" );
   
   protected STSCoreConfig configuration;
   
   private static PicketLinkCoreSTS _instance = null;
   
   protected PicketLinkCoreSTS()
   {   
   }
   
   public static PicketLinkCoreSTS instance()
   {
      if( _instance == null )
         _instance = new PicketLinkCoreSTS();
      
      return _instance;
   }
   
   public void initialize( STSCoreConfig config )
   {
      if( this.configuration != null )
      {
         List<SecurityTokenProvider> providers = config.getTokenProviders();
         for( SecurityTokenProvider provider: providers )
         this.configuration.addTokenProvider( provider.tokenType(), provider );
      } 
      else
         this.configuration = config;
   }
   
   public void installDefaultConfiguration()
   {
      if( configuration == null )
         configuration = new PicketLinkSTSConfiguration();
      
      //SAML2 Specification Provider
      configuration.addTokenProvider( SAML20AssertionTokenProvider.NS, new SAML20AssertionTokenProvider() );
   }
   
   /**
    * Issue a security token
    * @param protocolContext
    * @throws ProcessingException
    * @throws {@link SecurityException} if the caller does not have a runtime permission for "org.picketlink.sts"
    */
   public void issueToken( ProtocolContext protocolContext) throws ProcessingException
   { 
      SecurityManager sm = System.getSecurityManager();
      if( sm != null )
         sm.checkPermission( rte );
      
      SecurityTokenProvider provider = getProvider(protocolContext);  
      
      if( provider == null )
         throw new ProcessingException( "No Security Token Provider found in configuration" );
      
      provider.issueToken( protocolContext );
   }

   /**
    * <p>
    * Renews the security token contained in the specified request context. This method is used when a previously
    * generated token has expired, generating a new version of the same token with different expiration semantics.
    * </p>
    * 
    * @param protocolContext the {@code ProtocolContext} that contains the token to be renewed.
    * @throws ProcessingException if an error occurs while renewing the security token.
    * @throws {@link SecurityException} if the caller does not have a runtime permission for "org.picketlink.sts"
    */
   public void renewToken( ProtocolContext protocolContext) throws ProcessingException
   { 
      SecurityManager sm = System.getSecurityManager();
      if( sm != null )
         sm.checkPermission( rte );
      
      SecurityTokenProvider provider = null;
      
      if( provider == null )
         provider = getProviderBasedOnQName(protocolContext);
 
      provider.renewToken( protocolContext ); 
   }

   /**
    * <p>
    * Cancels the token contained in the specified request context. A security token is usually canceled when one wants
    * to make sure that the token will not be used anymore. A security token can't be renewed once it has been canceled.
    * </p>
    * 
    * @param protocolContext the {@code ProtocolContext} that contains the token to be canceled.
    * @throws ProcessingException if an error occurs while canceling the security token.
    * @throws {@link SecurityException} if the caller does not have a runtime permission for "org.picketlink.sts"
    */
   public void cancelToken( ProtocolContext protocolContext) throws ProcessingException
   {
      SecurityManager sm = System.getSecurityManager();
      if( sm != null )
         sm.checkPermission( rte );
      
      SecurityTokenProvider provider = null;
      
      if( provider == null )
         provider = getProviderBasedOnQName(protocolContext);
 
      provider.cancelToken( protocolContext ); 
   }

   /**
    * <p>
    * Evaluates the validity of the token contained in the specified request context and sets the result in the context
    * itself. The result can be a status, a new token, or both.
    * </p>
    * 
    * @param protocolContext the {@code ProtocolContext} that contains the token to be validated.
    * @throws ProcessingException if an error occurs while validating the security token.
    * @throws {@link SecurityException} if the caller does not have a runtime permission for "org.picketlink.sts"
    */
   public void validateToken( ProtocolContext protocolContext) throws ProcessingException
   {
      SecurityManager sm = System.getSecurityManager();
      if( sm != null )
         sm.checkPermission( rte );
      
      SecurityTokenProvider provider = null;
      
      if( provider == null )
         provider = getProviderBasedOnQName(protocolContext);
 
      provider.validateToken( protocolContext );     
   }
   
   private SecurityTokenProvider getProvider( ProtocolContext protocolContext )
   {
      if( configuration == null )
         throw new RuntimeException( "Configuration is not set" );
      
      SecurityTokenProvider provider = null;
      
      //Special Case: WST Applies To
      String serviceName = protocolContext.serviceName();
      if (serviceName != null)
      {
         provider = this.configuration.getProviderForService( serviceName ); 
      }
      
      if( provider == null )
      {
         //lets get the provider based on token type
         String tokenType = protocolContext.tokenType();
         if( tokenType != null )
            provider = this.configuration.getProviderForTokenType( protocolContext.tokenType() );
      }
      return provider;
   }
   
   private SecurityTokenProvider getProviderBasedOnQName( ProtocolContext protocolContext ) throws ProcessingException
   {
      SecurityTokenProvider provider = null;
      
      QName qname = null;
      if( provider == null )
      {
         qname = protocolContext.getQName();
         if( qname == null )
            throw new ProcessingException( "QName of the token type is null " );
         provider = this.configuration.getProviderForTokenElementNS(qname.getLocalPart(),
               qname.getNamespaceURI());  
      }
      
       
      if (provider == null)
         throw new ProcessingException("No SecurityTokenProvider configured for " + qname.getNamespaceURI() + ":"
               + qname.getLocalPart() );
      
      return provider;
   }
}