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
package org.jboss.identity.federation.web.handlers.saml2;

import java.security.PublicKey;

import org.apache.log4j.Logger;
import org.jboss.identity.federation.core.exceptions.ConfigurationException;
import org.jboss.identity.federation.core.exceptions.ProcessingException;
import org.jboss.identity.federation.core.saml.v2.interfaces.SAML2HandlerRequest;
import org.jboss.identity.federation.core.saml.v2.interfaces.SAML2HandlerResponse;
import org.jboss.identity.federation.core.saml.v2.util.DocumentUtil;
import org.jboss.identity.federation.core.util.XMLSignatureUtil;
import org.jboss.identity.federation.web.constants.GeneralConstants;
import org.w3c.dom.Document;

/**
 * @author Anil.Saldhana@redhat.com
 * @since Nov 13, 2009
 */
public class SAML2SignatureValidationHandler extends BaseSAML2Handler
{
   private static Logger log = Logger.getLogger(SAML2SignatureValidationHandler.class); 
   private boolean trace = log.isTraceEnabled();
   
   /**
    * @see {@code SAML2Handler#handleRequestType(SAML2HandlerRequest, SAML2HandlerResponse)}
    */
   public void handleRequestType(SAML2HandlerRequest request, SAML2HandlerResponse response) throws ProcessingException
   {
      Document signedDocument = request.getRequestDocument();
      if(trace)
      {
         try
         {
            log.trace("Will validate :" + DocumentUtil.getDocumentAsString(signedDocument));
         }
         catch (ConfigurationException e)
         { 
         } 
      }
      PublicKey publicKey = (PublicKey) request.getOptions().get(GeneralConstants.SENDER_PUBLIC_KEY);
      this.validateSender(signedDocument, publicKey);
   }

   @Override
   public void handleStatusResponseType(SAML2HandlerRequest request, SAML2HandlerResponse response)
         throws ProcessingException
   {  
      Document signedDocument = request.getRequestDocument();
      PublicKey publicKey = (PublicKey) request.getOptions().get(GeneralConstants.SENDER_PUBLIC_KEY);
      this.validateSender(signedDocument, publicKey);
   }
   
   private void validateSender(Document signedDocument, PublicKey publicKey) 
   throws ProcessingException
   {
      try
      {
         XMLSignatureUtil.validate(signedDocument, publicKey);
      }
      catch (Exception e)
      {
         log.error("Error validating signature:" , e);
         throw new ProcessingException("Error validating signature.");
      }  
   } 
}