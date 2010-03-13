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
package org.picketlink.identity.federation.bindings.jboss.auth;

import java.security.Principal;
import java.security.acl.Group;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.xml.bind.JAXBElement;

import org.jboss.security.auth.callback.ObjectCallback;
import org.jboss.security.auth.spi.AbstractServerLoginModule;
import org.picketlink.identity.federation.bindings.jboss.subject.PicketLinkGroup;
import org.picketlink.identity.federation.bindings.jboss.subject.PicketLinkPrincipal;
import org.picketlink.identity.federation.core.wstrust.STSClient;
import org.picketlink.identity.federation.core.wstrust.SamlCredential;
import org.picketlink.identity.federation.core.wstrust.WSTrustException;
import org.picketlink.identity.federation.core.wstrust.STSClientConfig.Builder;
import org.picketlink.identity.federation.core.wstrust.plugins.saml.SAMLUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.StatementAbstractType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;
import org.w3c.dom.Element;

/**
 * <p>
 * This {@code LoginModule} authenticates clients by validating their SAML assertions with an external security
 * token service (such as PicketLinkSTS). If the supplied assertion contains roles, these roles are extracted
 * and included in the {@code Group} returned by the {@code getRoleSets} method.
 * </p>
 * <p>
 * This module defines one module option:
 * <li>
 *  <ul>configFile - this property identifies the properties file that will be used to establish communication with
 *  the external security token service.
 *  </ul>
 * </li>
 * An example of a {@code configFile} can be seen bellow:
 * <pre>
 * serviceName=PicketLinkSTS
 * portName=PicketLinkSTSPort
 * endpointAddress=http://localhost:8080/picketlink-sts-1.0.0/PicketLinkSTS
 * username=JBoss
 * password=JBoss
 * </pre>
 * The first three properties specify the STS endpoint URL, service name, and port name. The last two properties
 * specify the username and password that are to be used by the application server to authenticate to the STS and
 * have the SAML assertions validated.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
@SuppressWarnings("unchecked")
public class SAML2STSLoginModule extends AbstractServerLoginModule
{

   private String stsConfigurationFile;

   private Principal principal;

   private SamlCredential credential;

   private AssertionType assertion;

   /*
    * (non-Javadoc)
    * @see org.jboss.security.auth.spi.AbstractServerLoginModule#initialize(javax.security.auth.Subject, javax.security.auth.callback.CallbackHandler, java.util.Map, java.util.Map)
    */
   @Override
   public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
         Map<String, ?> options)
   {
      super.initialize(subject, callbackHandler, sharedState, options);
      // check if the options contain the name of the STS configuration file.
      this.stsConfigurationFile = (String) options.get("configFile");
   }

   /*
    * (non-Javadoc)
    * @see org.jboss.security.auth.spi.AbstractServerLoginModule#login()
    */
   @Override
   public boolean login() throws LoginException
   {
      // if shared data exists, set our principal and assertion variables.
      if (super.login())
      {
         Object sharedPrincipal = super.sharedState.get("javax.security.auth.login.name");
         if (sharedPrincipal instanceof Principal)
            this.principal = (Principal) sharedPrincipal;
         else
         {
            try
            {
               this.principal = createIdentity(sharedPrincipal.toString());
            }
            catch (Exception e)
            {
               throw new LoginException("Failed to create principal: " + e.getMessage());
            }
         }

         Object credential = super.sharedState.get("javax.security.auth.login.password");
         if (credential instanceof SamlCredential)
            this.credential = (SamlCredential) credential;
         else
            throw new LoginException("Shared credential is not a SAML credential");
         return true;
      }

      // if there is no shared data, validate the assertion using the STS.
      if (this.stsConfigurationFile == null)
         throw new LoginException("Failed to validate assertion: STS configuration file not specified");

      // obtain the assertion from the callback handler.
      ObjectCallback callback = new ObjectCallback(null);
      Element assertionElement = null;
      try
      {
         super.callbackHandler.handle(new Callback[]{callback});
         if (callback.getCredential() instanceof SamlCredential == false)
            throw new IllegalArgumentException("Supplied credential is not a SAML credential");
         this.credential = (SamlCredential) callback.getCredential();
         assertionElement = this.credential.getAssertionAsElement();
      }
      catch (Exception e)
      {
         LoginException exception = new LoginException("Error handling callback" + e.getMessage());
         exception.initCause(e);
         throw exception;
      }

      // send the assertion to the STS for validation.
      Builder builder = new Builder(this.stsConfigurationFile);
      STSClient client = new STSClient(builder.build());
      try
      {
         boolean isValid = client.validateToken(assertionElement);
         // if the STS says the assertion is invalid, throw an exception to signal that authentication has failed.
         if (isValid == false)
            throw new LoginException("Supplied assertion was considered invalid by the STS");
      }
      catch (WSTrustException we)
      {
         LoginException exception = new LoginException("Failed to validate assertion using STS: " + we.getMessage());
         exception.initCause(we);
         throw exception;
      }

      // if the assertion is valid, create a principal containing the assertion subject.
      try
      {
         this.assertion = SAMLUtil.fromElement(assertionElement);
         SubjectType subject = assertion.getSubject();
         if (subject != null)
         {
            for (JAXBElement<?> element : subject.getContent())
            {
               if (element.getDeclaredType().equals(NameIDType.class))
               {
                  NameIDType nameID = (NameIDType) element.getValue();
                  this.principal = new PicketLinkPrincipal(nameID.getValue());
                  break;
               }
            }
         }
      }
      catch (Exception e)
      {
         LoginException exception = new LoginException("Failed to parse assertion element" + e.getMessage());
         exception.initCause(e);
         throw exception;
      }

      // if password-stacking has been configured, set the principal and the assertion in the shared map.
      if (getUseFirstPass())
      {
         super.sharedState.put("javax.security.auth.login.name", this.principal);
         super.sharedState.put("javax.security.auth.login.password", this.credential);
      }
      return (super.loginOk = true);
   }

   /*
    * (non-Javadoc)
    * @see org.jboss.security.auth.spi.AbstractServerLoginModule#getIdentity()
    */
   @Override
   protected Principal getIdentity()
   {
      return this.principal;
   }

   /*
    * (non-Javadoc)
    * @see org.jboss.security.auth.spi.AbstractServerLoginModule#getRoleSets()
    */
   @Override
   protected Group[] getRoleSets() throws LoginException
   {
      if (this.assertion == null)
      {
         try
         {
            this.assertion = SAMLUtil.fromElement(this.credential.getAssertionAsElement());
         }
         catch (Exception e)
         {
            LoginException le = new LoginException("Failed to parse assertion element: " + e.getMessage());
            le.initCause(e);
            throw le;
         }
      }

      // check the assertion statements and look for role attributes.
      AttributeStatementType attributeStatement = this.getAttributeStatement(this.assertion);
      if (attributeStatement != null)
      {
         Set<Principal> roles = new HashSet<Principal>();
         List<Object> attributeList = attributeStatement.getAttributeOrEncryptedAttribute();
         for (Object obj : attributeList)
         {
            if (obj instanceof AttributeType)
            {
               AttributeType attribute = (AttributeType) obj;
               // if this is a role attribute, get its values and add them to the role set.
               if (attribute.getName().equals("role"))
               {
                  for (Object value : attribute.getAttributeValue())
                     roles.add(new PicketLinkPrincipal((String) value));
               }
            }
         }
         Group rolesGroup = new PicketLinkGroup("Roles");
         for (Principal role : roles)
            rolesGroup.addMember(role);
         return new Group[]{rolesGroup};
      }
      return new Group[0];
   }
   
   /**
    * <p>
    * Checks if the specified SAML assertion contains a {@code AttributeStatementType} and returns this type when it
    * is available.
    * </p>
    * 
    * @param assertion a reference to the {@code AssertionType} that may contain an {@code AttributeStatementType}.
    * @return the assertion's {@code AttributeStatementType}, or {@code null} if no such type can be found in the SAML
    * assertion.
    */
   private AttributeStatementType getAttributeStatement(AssertionType assertion)
   {
      List<StatementAbstractType> statementList = assertion.getStatementOrAuthnStatementOrAuthzDecisionStatement();
      if (statementList.size() != 0)
      {
         for (StatementAbstractType statement : statementList)
         {
            if (statement instanceof AttributeStatementType)
               return (AttributeStatementType) statement;
         }
      }
      return null;
   }
}