/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2009, Red Hat Middleware LLC, and individual contributors
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
package org.picketlink.identity.federation.core.wstrust.plugins.saml;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.bind.JAXBException;
import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.picketlink.identity.federation.core.saml.v2.common.IDGenerator;
import org.picketlink.identity.federation.core.saml.v2.factories.SAMLAssertionFactory;
import org.picketlink.identity.federation.core.saml.v2.util.AssertionUtil;
import org.picketlink.identity.federation.core.saml.v2.util.StatementUtil;
import org.picketlink.identity.federation.core.wstrust.SecurityToken;
import org.picketlink.identity.federation.core.wstrust.SecurityTokenProvider;
import org.picketlink.identity.federation.core.wstrust.StandardSecurityToken;
import org.picketlink.identity.federation.core.wstrust.WSTrustConstants;
import org.picketlink.identity.federation.core.wstrust.WSTrustException;
import org.picketlink.identity.federation.core.wstrust.WSTrustRequestContext;
import org.picketlink.identity.federation.core.wstrust.WSTrustUtil;
import org.picketlink.identity.federation.core.wstrust.wrappers.Lifetime;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.AudienceRestrictionType;
import org.picketlink.identity.federation.saml.v2.assertion.ConditionsType;
import org.picketlink.identity.federation.saml.v2.assertion.KeyInfoConfirmationDataType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.StatementAbstractType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectConfirmationType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;
import org.picketlink.identity.federation.ws.policy.AppliesTo;
import org.picketlink.identity.federation.ws.trust.RequestedReferenceType;
import org.picketlink.identity.federation.ws.trust.StatusType;
import org.picketlink.identity.federation.ws.wss.secext.KeyIdentifierType;
import org.w3c.dom.Element;

/**
 * <p>
 * A {@code SecurityTokenProvider} implementation that handles WS-Trust SAML 2.0 token requests.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class SAML20TokenProvider implements SecurityTokenProvider
{

   private static Logger logger = Logger.getLogger(SAML20TokenProvider.class);

   private static final String CANCELED_IDS_FILE = "CanceledIdsFile";

   // this set contains the ids of the assertions that have been canceled.
   private Set<String> cancelledIds;

   // file used to store the ids of the canceled assertions.
   private File canceledIdsFile;

   private Map<String, String> properties;

   /*
    * (non-Javadoc)
    * 
    * @see org.picketlink.identity.federation.core.wstrust.SecurityTokenProvider#initialize(java.util.Map)
    */
   public void initialize(Map<String, String> properties)
   {
      this.properties = properties;
      this.cancelledIds = new HashSet<String>();

      // set up the canceled ids cache if the file that contains the canceled assertions has been specified.
      String file = this.properties.get(CANCELED_IDS_FILE);
      if (file == null && logger.isDebugEnabled())
         logger.debug("File to store canceled ids has not been specified: ids will not be persisted!");
      else if (file != null)
      {
         this.canceledIdsFile = new File(file);
         this.loadCanceledIds();
      }
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.picketlink.identity.federation.core.wstrust.SecurityTokenProvider#
    * 	cancelToken(org.picketlink.identity.federation.core.wstrust.WSTrustRequestContext)
    */
   public void cancelToken(WSTrustRequestContext context) throws WSTrustException
   {
      // get the assertion that must be canceled.
      Element token = (Element) context.getRequestSecurityToken().getCancelTargetElement();
      if (token == null)
         throw new WSTrustException("Invalid cancel request: missing required CancelTarget");
      Element assertionElement = (Element) token.getFirstChild();
      if (!this.isAssertion(assertionElement))
         throw new WSTrustException("CancelTarget doesn't not contain a SAMLV2.0 assertion");

      // get the assertion ID and add it to the canceled assertions set.
      String assertionId = assertionElement.getAttribute("ID");
      this.storeCanceledId(assertionId);
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.picketlink.identity.federation.core.wstrust.SecurityTokenProvider#
    * 	issueToken(org.picketlink.identity.federation.core.wstrust.WSTrustRequestContext)
    */
   public void issueToken(WSTrustRequestContext context) throws WSTrustException
   {
      // generate an id for the new assertion.
      String assertionID = IDGenerator.create("ID_");

      // lifetime and audience restrictions.
      Lifetime lifetime = context.getRequestSecurityToken().getLifetime();
      AudienceRestrictionType restriction = null;
      AppliesTo appliesTo = context.getRequestSecurityToken().getAppliesTo();
      if (appliesTo != null)
         restriction = SAMLAssertionFactory.createAudienceRestriction(WSTrustUtil.parseAppliesTo(appliesTo));
      ConditionsType conditions = SAMLAssertionFactory.createConditions(lifetime.getCreated(), lifetime.getExpires(),
            restriction);

      String confirmationMethod = null;
      KeyInfoConfirmationDataType keyInfoDataType = null;
      // if there is a proof-of-possession token in the context, we have the holder of key confirmation method.
      if (context.getProofTokenInfo() != null)
      {
         confirmationMethod = SAMLUtil.SAML2_HOLDER_OF_KEY_URI;
         keyInfoDataType = SAMLAssertionFactory.createKeyInfoConfirmation(context.getProofTokenInfo());
      }
      else
         confirmationMethod = SAMLUtil.SAML2_BEARER_URI;
      // TODO: implement the SENDER_VOUCHES scenario.

      SubjectConfirmationType subjectConfirmation = SAMLAssertionFactory.createSubjectConfirmation(null,
            confirmationMethod, keyInfoDataType);

      // create a subject using the caller principal.
      Principal principal = context.getCallerPrincipal();
      String subjectName = principal == null ? "ANONYMOUS" : principal.getName();
      NameIDType nameID = SAMLAssertionFactory.createNameID(null, "urn:picketlink:identity-federation", subjectName);
      SubjectType subject = SAMLAssertionFactory.createSubject(nameID, subjectConfirmation);

      // create the attribute statements if necessary.
      List<StatementAbstractType> statements = null;
      Map<String, Object> claimedAttributes = context.getClaimedAttributes();
      if (claimedAttributes != null)
      {
         statements = new ArrayList<StatementAbstractType>();
         statements.add(StatementUtil.createAttributeStatement(claimedAttributes));
      }

      // create the SAML assertion.
      NameIDType issuerID = SAMLAssertionFactory.createNameID(null, null, context.getTokenIssuer());
      AssertionType assertion = SAMLAssertionFactory.createAssertion(assertionID, issuerID, lifetime.getCreated(),
            conditions, subject, statements);

      // convert the constructed assertion to element.
      Element assertionElement = null;
      try
      {
         assertionElement = SAMLUtil.toElement(assertion);
      }
      catch (Exception e)
      {
         throw new WSTrustException("Failed to marshall SAMLV2 assertion", e);
      }

      SecurityToken token = new StandardSecurityToken(context.getRequestSecurityToken().getTokenType().toString(),
            assertionElement, assertionID);
      context.setSecurityToken(token);

      // set the SAML assertion attached reference.
      KeyIdentifierType keyIdentifier = WSTrustUtil.createKeyIdentifier(SAMLUtil.SAML2_VALUE_TYPE, "#" + assertionID);
      Map<QName, String> attributes = new HashMap<QName, String>();
      attributes.put(new QName(WSTrustConstants.WSSE11_NS, "TokenType"), SAMLUtil.SAML2_TOKEN_TYPE);
      RequestedReferenceType attachedReference = WSTrustUtil.createRequestedReference(keyIdentifier, attributes);
      context.setAttachedReference(attachedReference);
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.picketlink.identity.federation.core.wstrust.SecurityTokenProvider#
    * 	renewToken(org.picketlink.identity.federation.core.wstrust.WSTrustRequestContext)
    */
   public void renewToken(WSTrustRequestContext context) throws WSTrustException
   {
      // get the specified assertion that must be renewed.
      Element token = (Element) context.getRequestSecurityToken().getRenewTargetElement();
      if (token == null)
         throw new WSTrustException("Invalid renew request: missing required RenewTarget");
      Element oldAssertionElement = (Element) token.getFirstChild();
      if (!this.isAssertion(oldAssertionElement))
         throw new WSTrustException("RenewTarget doesn't not contain a SAMLV2.0 assertion");

      // get the JAXB representation of the old assertion.
      AssertionType oldAssertion = null;
      try
      {
         oldAssertion = SAMLUtil.fromElement(oldAssertionElement);
      }
      catch (JAXBException je)
      {
         throw new WSTrustException("Error unmarshalling assertion", je);
      }

      // canceled assertions cannot be renewed.
      if (this.cancelledIds.contains(oldAssertion.getID()))
         throw new WSTrustException("Assertion with id " + oldAssertion.getID() + " is canceled and cannot be renewed");

      // adjust the lifetime for the renewed assertion.
      ConditionsType conditions = oldAssertion.getConditions();
      conditions.setNotBefore(context.getRequestSecurityToken().getLifetime().getCreated());
      conditions.setNotOnOrAfter(context.getRequestSecurityToken().getLifetime().getExpires());

      // create a new unique ID for the renewed assertion.
      String assertionID = IDGenerator.create("ID_");

      // create the new assertion.
      AssertionType newAssertion = SAMLAssertionFactory.createAssertion(assertionID, oldAssertion.getIssuer(), context
            .getRequestSecurityToken().getLifetime().getCreated(), conditions, oldAssertion.getSubject(), oldAssertion
            .getStatementOrAuthnStatementOrAuthzDecisionStatement());

      // create a security token with the new assertion.
      Element assertionElement = null;
      try
      {
         assertionElement = SAMLUtil.toElement(newAssertion);
      }
      catch (Exception e)
      {
         throw new WSTrustException("Failed to marshall SAMLV2 assertion", e);
      }
      SecurityToken securityToken = new StandardSecurityToken(context.getRequestSecurityToken().getTokenType()
            .toString(), assertionElement, assertionID);
      context.setSecurityToken(securityToken);

      // set the SAML assertion attached reference.
      KeyIdentifierType keyIdentifier = WSTrustUtil.createKeyIdentifier(SAMLUtil.SAML2_VALUE_TYPE, "#" + assertionID);
      Map<QName, String> attributes = new HashMap<QName, String>();
      attributes.put(new QName(WSTrustConstants.WSSE11_NS, "TokenType"), SAMLUtil.SAML2_TOKEN_TYPE);
      RequestedReferenceType attachedReference = WSTrustUtil.createRequestedReference(keyIdentifier, attributes);
      context.setAttachedReference(attachedReference);
   }

   /*
    * (non-Javadoc)
    * 
    * @see org.picketlink.identity.federation.core.wstrust.SecurityTokenProvider#
    * 	validateToken(org.picketlink.identity.federation.core.wstrust.WSTrustRequestContext)
    */
   public void validateToken(WSTrustRequestContext context) throws WSTrustException
   {
      if (logger.isTraceEnabled())
         logger.trace("SAML V2.0 token validation started");

      // get the SAML assertion that must be validated.
      Element token = context.getRequestSecurityToken().getValidateTargetElement();
      if (token == null)
         throw new WSTrustException("Bad validate request: missing required ValidateTarget");

      String code = WSTrustConstants.STATUS_CODE_VALID;
      String reason = "SAMLV2.0 Assertion successfuly validated";

      AssertionType assertion = null;
      Element assertionElement = (Element) token.getFirstChild();
      if (!this.isAssertion(assertionElement))
      {
         code = WSTrustConstants.STATUS_CODE_INVALID;
         reason = "Validation failure: supplied token is not a SAMLV2.0 Assertion";
      }
      else
      {
         try
         {
            assertion = SAMLUtil.fromElement(assertionElement);
         }
         catch (JAXBException e)
         {
            throw new WSTrustException("Unmarshalling error:", e);
         }
      }

      // check if the assertion has been canceled before.
      if (this.cancelledIds.contains(assertion.getID()))
      {
         code = WSTrustConstants.STATUS_CODE_INVALID;
         reason = "Validation failure: assertion with id " + assertion.getID() + " is canceled";
      }

      // check the assertion lifetime.
      try
      {
         if (AssertionUtil.hasExpired(assertion))
         {
            code = WSTrustConstants.STATUS_CODE_INVALID;
            reason = "Validation failure: assertion expired or used before its lifetime period";
         }
      }
      catch (Exception ce)
      {
         code = WSTrustConstants.STATUS_CODE_INVALID;
         reason = "Validation failure: unable to verify assertion lifetime: " + ce.getMessage();
      }

      // construct the status and set it on the request context.
      StatusType status = new StatusType();
      status.setCode(code);
      status.setReason(reason);
      context.setStatus(status);
   }

   /**
    * <p>
    * Checks whether the specified element is a SAMLV2.0 assertion or not.
    * </p>
    *  
    * @param element the {@code Element} being verified.
    * @return {@code true} if the element is a SAMLV2.0 assertion; {@code false} otherwise.
    */
   private boolean isAssertion(Element element)
   {
      return element == null ? false : "Assertion".equals(element.getLocalName())
            && WSTrustConstants.SAML2_ASSERTION_NS.equals(element.getNamespaceURI());
   }

   /**
    * <p>
    * This method loads the ids of the canceled assertions from the file that has been configured for this provider.
    * All retrieved ids are set in the local cache of canceled ids.
    * </p>
    */
   private void loadCanceledIds()
   {
      try
      {
         if (!this.canceledIdsFile.exists())
         {
            if (logger.isDebugEnabled())
               logger.debug("File " + this.canceledIdsFile.getCanonicalPath() + " doesn't exist and will be created");
            this.canceledIdsFile.createNewFile();
         }
         // read the file contents and populate the local cache.
         BufferedReader reader = new BufferedReader(new FileReader(this.canceledIdsFile));
         String id = reader.readLine();
         while(id != null)
         {
            this.cancelledIds.add(id);
            id = reader.readLine();
         }
         reader.close();
      }
      catch (IOException ioe)
      {
         if (logger.isDebugEnabled())
            logger.debug("Error opening canceled ids file: " + ioe.getMessage());
         ioe.printStackTrace();
      }
   }
   
   /**
    * <p>
    * Stores the specified id in the cache of canceled ids. If a canceled ids file has been configured for this 
    * provider, the id will also be written to the end of the file.
    * </p>
    * 
    * @param id a {@code String} representing the canceled id that must be stored.
    */
   public synchronized void storeCanceledId(String id)
   {
      if (this.canceledIdsFile != null)
      {
         try
         {
            // write a new line with the canceled id at the end of the file. 
            BufferedWriter writer = new BufferedWriter(new FileWriter(this.canceledIdsFile, true));
            writer.write(id + "\n");
            writer.close();
         }
         catch (IOException e)
         {
            e.printStackTrace();
         }
      }
      // add the canceled id to the local cache.
      this.cancelledIds.add(id);
   }
}