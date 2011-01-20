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
package org.picketlink.identity.federation.core.openid.providers;

import javax.xml.namespace.QName;

import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.interfaces.ProtocolContext;
import org.picketlink.identity.federation.core.interfaces.SecurityTokenProvider;
import org.picketlink.identity.federation.core.openid.providers.helpers.OpenIDParameterList;
import org.picketlink.identity.federation.core.openid.providers.helpers.OpenIDProtocolContext;
import org.picketlink.identity.federation.core.openid.providers.helpers.OpenIDProtocolContext.AUTH_HOLDER;
import org.picketlink.identity.federation.core.openid.providers.helpers.OpenIDProtocolContext.MODE;
import org.picketlink.identity.federation.core.openid.providers.helpers.OpenIDProviderManager;
import org.picketlink.identity.federation.core.openid.providers.helpers.OpenIDTokenRegistryStore;
import org.picketlink.identity.federation.core.openid.providers.helpers.OpenIDProviderManager.OpenIDMessage;
import org.picketlink.identity.federation.core.sts.AbstractSecurityTokenProvider;
import org.picketlink.identity.federation.core.sts.PicketLinkCoreSTS;

/**
 * @author Anil.Saldhana@redhat.com
 * @since Jan 20, 2011
 */
public class OpenIDTokenProvider extends AbstractSecurityTokenProvider implements SecurityTokenProvider
{ 
   public final static String OPENID_1_0_NS = "urn:openid:1:0";
   public final static String OPENID_1_1_NS = "urn:openid:1:1";
   public final static String OPENID_2_0_NS = "urn:openid:2:0";
   
   protected static OpenIDProviderManager serverManager = null; //Will be initialized the first time of access
   
   /**
    * @see org.picketlink.identity.federation.core.interfaces.SecurityTokenProvider#supports(java.lang.String)
    */
   public boolean supports(String namespace)
   { 
      return OPENID_1_0_NS.equals( namespace );
   }

   /**
    * @see org.picketlink.identity.federation.core.interfaces.SecurityTokenProvider#tokenType()
    */
   public String tokenType()
   { 
      return OPENID_1_0_NS;
   }

   /**
    * @see org.picketlink.identity.federation.core.interfaces.SecurityTokenProvider#getSupportedQName()
    */
   public QName getSupportedQName()
   { 
      return new QName( OPENID_1_0_NS );
   }

   /**
    * @see org.picketlink.identity.federation.core.interfaces.SecurityTokenProvider#family()
    */
   public String family()
   { 
      return SecurityTokenProvider.FAMILY_TYPE.OPENID.name();
   }

   /**
    * @see org.picketlink.identity.federation.core.interfaces.SecurityTokenProvider#issueToken(org.picketlink.identity.federation.core.interfaces.ProtocolContext)
    */
   public void issueToken(ProtocolContext context) throws ProcessingException
   { 
      if( context instanceof OpenIDProtocolContext == false )
         return;
      
      check();
      
      OpenIDProtocolContext openIDProtoCtx = (OpenIDProtocolContext) context;
      if( serverManager.getEndPoint() == null )
      {
         serverManager.setEndPoint( openIDProtoCtx.getEndpoint() );
      }
      
      OpenIDParameterList requestp = openIDProtoCtx.getRequestParameterList();
      OpenIDMessage responsem = null;
      
      if( openIDProtoCtx.getIssueError() )
      {
         String errorText = openIDProtoCtx.getErrorText() == null ? "Unknown request" : openIDProtoCtx.getErrorText();
         
         responsem = serverManager.getDirectError( errorText );
      }
      else
      {
         MODE mode = openIDProtoCtx.getMode();
         switch (mode )
         {
            case ASSOCIATE :
               responsem = serverManager.processAssociationRequest( requestp );
               break;
            
            case CHECK_AUTHENTICATION:
               validateToken(openIDProtoCtx);
               return;
            
            case CHECK_ID_SETUP:
            case CHECK_ID_IMMEDIATE:
               AUTH_HOLDER authHolder = openIDProtoCtx.getAuthenticationHolder();
               if( authHolder == null )
                  throw new ProcessingException( "Authentication Holder is null" );
               
               responsem = serverManager.processAuthenticationRequest(requestp,
                     authHolder.getUserSelectedId(),
                     authHolder.getUserSelectedClaimedId(),
                     authHolder.isAuthenticatedAndApproved() );
               break;
            default:
               throw new ProcessingException("Unknown mode"); 
         } 
      }
      openIDProtoCtx.setResponseMessage( responsem );
   }

   /**
    * @see org.picketlink.identity.federation.core.interfaces.SecurityTokenProvider#renewToken(org.picketlink.identity.federation.core.interfaces.ProtocolContext)
    */
   public void renewToken(ProtocolContext context) throws ProcessingException
   { 
      if( context instanceof OpenIDProtocolContext == false )
         return;
      
      check();
   }

   /*
    * @see org.picketlink.identity.federation.core.interfaces.SecurityTokenProvider#cancelToken(org.picketlink.identity.federation.core.interfaces.ProtocolContext)
    */
   public void cancelToken(ProtocolContext context) throws ProcessingException
   { 
      if( context instanceof OpenIDProtocolContext == false )
         return;
      
      check();
   }

   /**
    * @see org.picketlink.identity.federation.core.interfaces.SecurityTokenProvider#validateToken(org.picketlink.identity.federation.core.interfaces.ProtocolContext)
    */
   public void validateToken(ProtocolContext context) throws ProcessingException
   { 
      if( context instanceof OpenIDProtocolContext == false )
         return;
      
       check();
      
      OpenIDProtocolContext openIDProtoCtx = (OpenIDProtocolContext) context;
      if( serverManager.getEndPoint() == null )
      {
         serverManager.setEndPoint( openIDProtoCtx.getEndpoint() );
      }
      
      OpenIDParameterList requestp = openIDProtoCtx.getRequestParameterList();
      OpenIDMessage responsem = serverManager.verify( requestp );
      openIDProtoCtx.setResponseMessage( responsem );
   }
   
   protected void check()
   { 
      SecurityManager sm = System.getSecurityManager();
      if( sm != null )
         sm.checkPermission( PicketLinkCoreSTS.rte );
      
      if( serverManager == null )
      {

         serverManager = new OpenIDProviderManager();
         serverManager.initialize( new OpenIDTokenRegistryStore(), new OpenIDTokenRegistryStore()); 
      }
   }
}