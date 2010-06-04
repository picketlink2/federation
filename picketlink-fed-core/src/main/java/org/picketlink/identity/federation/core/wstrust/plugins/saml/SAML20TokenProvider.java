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

import java.security.Principal;
import java.security.PrivilegedActionException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
import org.picketlink.identity.federation.core.wstrust.plugins.DefaultRevocationRegistry;
import org.picketlink.identity.federation.core.wstrust.plugins.RevocationRegistry;
import org.picketlink.identity.federation.core.wstrust.plugins.FileBasedRevocationRegistry;
import org.picketlink.identity.federation.core.wstrust.plugins.JPABasedRevocationRegistry;
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

   private static final String REVOCATION_REGISTRY = "RevocationRegistry";

   private static final String REVOCATION_REGISTRY_FILE = "RevocationRegistryFile";

   private RevocationRegistry revocationRegistry;

   private Map<String, String> properties;

   /*
    * (non-Javadoc)
    * 
    * @see org.picketlink.identity.federation.core.wstrust.SecurityTokenProvider#initialize(java.util.Map)
    */
   public void initialize(Map<String, String> properties)
   {
      this.properties = properties;

      // check if a revocation registry option has been set.
      String registryOption = this.properties.get(REVOCATION_REGISTRY);
      if (registryOption == null)
      {
         if (logger.isDebugEnabled())
            logger.debug("Revocation registry option not specified: cancelled ids will not be persisted!");
         this.revocationRegistry = new DefaultRevocationRegistry();
      }
      else
      {
         // if a file is to be used as registry, check if the user has specified the file name.
         if ("FILE".equalsIgnoreCase(registryOption))
         {
            String registryFile = this.properties.get(REVOCATION_REGISTRY_FILE);
            if (registryFile != null)
               this.revocationRegistry = new FileBasedRevocationRegistry(registryFile);
            else
               this.revocationRegistry = new FileBasedRevocationRegistry();
         }
         // another option is to use the default JPA registry to store the revoked ids.
         else if ("JPA".equalsIgnoreCase(registryOption))
         {
            this.revocationRegistry = new JPABasedRevocationRegistry();
         }
         // the user has specified its own registry implementation class.
         else
         {
            try
            {
               Object object = SecurityActions.instantiateClass(registryOption);
               if (object instanceof RevocationRegistry)
                  this.revocationRegistry = (RevocationRegistry) object;
               else
               {
                  if (logger.isDebugEnabled())
                     logger.debug(registryOption + " is not an instance of RevocationRegistry - using default registry");
                  this.revocationRegistry = new DefaultRevocationRegistry();
               }
            }
            catch (PrivilegedActionException pae)
            {
               if (logger.isDebugEnabled())
                  logger.debug("Error instantiating revocation registry class - using default registry");
               pae.printStackTrace();
               this.revocationRegistry = new DefaultRevocationRegistry();
            }
         }
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
      this.revocationRegistry.revokeToken(SAMLUtil.SAML2_TOKEN_TYPE, assertionId);
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

      // the assertion principal (default is caller principal)
      Principal principal = context.getCallerPrincipal();

      String confirmationMethod = null;
      KeyInfoConfirmationDataType keyInfoDataType = null;
      // if there is a on-behalf-of principal, we have the sender vouches confirmation method.
      if (context.getOnBehalfOfPrincipal() != null)
      {
         principal = context.getOnBehalfOfPrincipal();
         confirmationMethod = SAMLUtil.SAML2_SENDER_VOUCHES_URI;
      }
      // if there is a proof-of-possession token in the context, we have the holder of key confirmation method.
      else if (context.getProofTokenInfo() != null)
      {
         confirmationMethod = SAMLUtil.SAML2_HOLDER_OF_KEY_URI;
         keyInfoDataType = SAMLAssertionFactory.createKeyInfoConfirmation(context.getProofTokenInfo());
      }
      else
         confirmationMethod = SAMLUtil.SAML2_BEARER_URI;

      SubjectConfirmationType subjectConfirmation = SAMLAssertionFactory.createSubjectConfirmation(null,
            confirmationMethod, keyInfoDataType);

      // create a subject using the caller principal or on-behalf-of principal.
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
      if (this.revocationRegistry.isRevoked(SAMLUtil.SAML2_TOKEN_TYPE, oldAssertion.getID()))
         throw new WSTrustException("Assertion with id " + oldAssertion.getID()
               + " has been canceled and cannot be renewed");

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
      if (this.revocationRegistry.isRevoked(SAMLUtil.SAML2_TOKEN_TYPE, assertion.getID()))
      {
         code = WSTrustConstants.STATUS_CODE_INVALID;
         reason = "Validation failure: assertion with id " + assertion.getID() + " has been canceled";
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

}