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

import java.security.KeyStore;
import java.security.Principal;
import java.security.PublicKey;
import java.security.acl.Group;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.transform.Source;
import javax.xml.ws.Dispatch;

import org.jboss.logging.Logger;
import org.jboss.security.SecurityConstants;
import org.jboss.security.auth.callback.ObjectCallback;
import org.jboss.security.auth.spi.AbstractServerLoginModule;
import org.jboss.security.plugins.JaasSecurityDomain;
import org.picketlink.identity.federation.bindings.jboss.subject.PicketLinkGroup;
import org.picketlink.identity.federation.bindings.jboss.subject.PicketLinkPrincipal;
import org.picketlink.identity.federation.core.factories.JBossAuthCacheInvalidationFactory;
import org.picketlink.identity.federation.core.factories.JBossAuthCacheInvalidationFactory.TimeCacheExpiry;
import org.picketlink.identity.federation.core.saml.v2.util.AssertionUtil;
import org.picketlink.identity.federation.core.util.StringUtil;
import org.picketlink.identity.federation.core.wstrust.STSClient;
import org.picketlink.identity.federation.core.wstrust.STSClientConfig.Builder;
import org.picketlink.identity.federation.core.wstrust.SamlCredential;
import org.picketlink.identity.federation.core.wstrust.WSTrustConstants;
import org.picketlink.identity.federation.core.wstrust.WSTrustException;
import org.picketlink.identity.federation.core.wstrust.plugins.saml.SAMLUtil;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AttributeStatementType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AttributeStatementType.ASTChoiceType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AttributeType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.BaseIDAbstractType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.StatementAbstractType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.SubjectType;
import org.w3c.dom.Element;

/**
 * <p>
 * This {@code LoginModule} authenticates clients by validating their SAML assertions with an external security
 * token service (such as PicketLinkSTS). If the supplied assertion contains roles, these roles are extracted
 * and included in the {@code Group} returned by the {@code getRoleSets} method.
 * </p>
 * <p>
 * This module defines the following module options:
 * <li>
 *  <ul>configFile - this property identifies the properties file that will be used to establish communication with
 *  the external security token service.
 *  </ul>
 *  <ul>cache.invalidation:  set it to true if you require invalidation of JBoss Auth Cache at SAML Principal expiration.
 *  </ul>
 *  <ul>jboss.security.security_domain: name of the security domain where this login module is configured. This is only required
 *  if the cache.invalidation option is configured.
 *  </ul>
 *  <ul>groupPrincipalName: if you do not want the Roles in the subject to be "Roles", then set it to a different value</ul>
 *  <ul>localValidation: if you want to validate the assertion locally for signature and expiry</ul>
 * </li>
 * </p>
 * <p>
 * Any properties specified besides the above properties are assumed to be used to configure how the {@code STSClient}
 * will connect to the STS. For example, the JBossWS {@code StubExt.PROPERTY_SOCKET_FACTORY} can be specified in order
 * to inform the socket factory that must be used to connect to the STS. All properties will be set in the request
 * context of the {@code Dispatch} instance used by the {@code STSClient} to send requests to the STS.  
 * </p>
 * <p>
 * An example of a {@code configFile} can be seen bellow:
 * <pre>
 * serviceName=PicketLinkSTS
 * portName=PicketLinkSTSPort
 * endpointAddress=http://localhost:8080/picketlink-sts/PicketLinkSTS
 * username=JBoss
 * password=JBoss
 * </pre>
 * The first three properties specify the STS endpoint URL, service name, and port name. The last two properties
 * specify the username and password that are to be used by the application server to authenticate to the STS and
 * have the SAML assertions validated.
 * </p>
 * <p>
 * <b>NOTE:</b> Sub-classes can use {@link #getSTSClient()} method to customize the {@link STSClient} class to make calls to STS/
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * @author Anil.Saldhana@redhat.com
 */
@SuppressWarnings("unchecked")
public class SAML2STSLoginModule extends AbstractServerLoginModule
{
   protected static Logger log = Logger.getLogger(SAML2STSLoginModule.class);

   protected boolean trace = log.isTraceEnabled();

   protected String stsConfigurationFile;

   protected Principal principal;

   protected SamlCredential credential;

   protected AssertionType assertion;

   protected boolean enableCacheInvalidation = false;

   protected String securityDomain = null;

   protected String groupName = "Roles";

   protected boolean localValidation = false;

   protected String localValidationSecurityDomain;

   protected Map<String, Object> options = new HashMap<String, Object>();

   /*
    * (non-Javadoc)
    * @see org.jboss.security.auth.spi.AbstractServerLoginModule#initialize(javax.security.auth.Subject, javax.security.auth.callback.CallbackHandler, java.util.Map, java.util.Map)
    */
   @Override
   public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
         Map<String, ?> options)
   {
      super.initialize(subject, callbackHandler, sharedState, options);
      this.options.putAll(options);
      // save the config file and cache validation options, removing them from the map - all remaining properties will
      // be set in the request context of the Dispatch instance used to send requests to the STS.
      this.stsConfigurationFile = (String) this.options.remove("configFile");
      String cacheInvalidation = (String) this.options.remove("cache.invalidation");
      if (cacheInvalidation != null && !cacheInvalidation.isEmpty())
      {
         this.enableCacheInvalidation = Boolean.parseBoolean(cacheInvalidation);

         this.securityDomain = (String) this.options.remove(SecurityConstants.SECURITY_DOMAIN_OPTION);
         if (this.securityDomain == null || this.securityDomain.isEmpty())
            throw new RuntimeException("Please configure option:" + SecurityConstants.SECURITY_DOMAIN_OPTION);
      }

      String groupNameStr = (String) options.get("groupPrincipalName");
      if (StringUtil.isNotNull(groupNameStr))
      {
         groupName = groupNameStr.trim();
      }

      String localValidationStr = (String) options.get("localValidation");
      if (StringUtil.isNotNull(localValidationStr))
      {
         localValidation = Boolean.parseBoolean(localValidationStr);
         localValidationSecurityDomain = (String) options.get("localValidationSecurityDomain");
      }
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
         super.callbackHandler.handle(new Callback[]
         {callback});
         if (callback.getCredential() instanceof SamlCredential == false)
            throw new IllegalArgumentException("Supplied credential is not a SAML credential.We got "
                  + callback.getCredential().getClass());
         this.credential = (SamlCredential) callback.getCredential();
         assertionElement = this.credential.getAssertionAsElement();
      }
      catch (Exception e)
      {
         LoginException exception = new LoginException("Error handling callback::" + e.getMessage());
         exception.initCause(e);
         throw exception;
      }

      if (localValidation)
      {
         try
         {
            boolean isValid = localValidation(assertionElement);
            if (isValid)
            {
               if (trace)
               {
                  log.trace("Local Validation passed.");
               }
            }
         }
         catch (Exception e)
         {
            LoginException le = new LoginException();
            le.initCause(e);
            throw le;
         }
      }
      else
      {
         // send the assertion to the STS for validation. 
         STSClient client = this.getSTSClient();
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
      }

      // if the assertion is valid, create a principal containing the assertion subject.
      try
      {
         this.assertion = SAMLUtil.fromElement(assertionElement);
         SubjectType subject = assertion.getSubject();
         if (subject != null)
         {
            BaseIDAbstractType baseID = subject.getSubType().getBaseID();
            if (baseID instanceof NameIDType)
            {
               NameIDType nameID = (NameIDType) baseID;
               this.principal = new PicketLinkPrincipal(nameID.getValue());

               //If the user has configured cache invalidation of subject based on saml token expiry
               if (enableCacheInvalidation)
               {
                  TimeCacheExpiry cacheExpiry = JBossAuthCacheInvalidationFactory.getCacheExpiry();
                  XMLGregorianCalendar expiry = AssertionUtil.getExpiration(assertion);
                  if (expiry != null)
                  {
                     cacheExpiry.register(securityDomain, expiry.toGregorianCalendar().getTime(), principal);
                  }
                  else
                  {
                     log.warn("SAML Assertion has been found to have no expiration: ID = " + assertion.getID());
                  }
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
         List<ASTChoiceType> attributeList = attributeStatement.getAttributes();
         for (ASTChoiceType obj : attributeList)
         {
            AttributeType attribute = obj.getAttribute();
            if (attribute != null)
            {
               // if this is a role attribute, get its values and add them to the role set.
               if (attribute.getName().equals("role"))
               {
                  for (Object value : attribute.getAttributeValue())
                     roles.add(new PicketLinkPrincipal((String) value));
               }
            }
         }
         Group rolesGroup = new PicketLinkGroup(groupName);
         for (Principal role : roles)
            rolesGroup.addMember(role);
         return new Group[]
         {rolesGroup};
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
      Set<StatementAbstractType> statementList = assertion.getStatements();
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

   /**
    * Get the {@link STSClient} object with which we can make calls to the STS
    * @return
    */
   protected STSClient getSTSClient()
   {
      Builder builder = new Builder(this.stsConfigurationFile);
      STSClient client = new STSClient(builder.build());
      // if the login module options map still contains any properties, assume they are for configuring the connection
      // to the STS and set them in the Dispatch request context.
      if (!this.options.isEmpty())
      {
         Dispatch<Source> dispatch = client.getDispatch();
         for (Map.Entry<String, ?> entry : this.options.entrySet())
            dispatch.getRequestContext().put(entry.getKey(), entry.getValue());
      }
      return client;
   }

   protected boolean localValidation(Element assertionElement) throws Exception
   {
      try
      {
         Context ctx = new InitialContext();
         JaasSecurityDomain sd = (JaasSecurityDomain) ctx.lookup(localValidationSecurityDomain);
         KeyStore ts = sd.getTrustStore();

         if (ts == null)
         {
            throw new LoginException("null truststore for " + sd.getName());
         }

         String alias = sd.getKeyStoreAlias();

         if (alias == null)
         {
            throw new LoginException("null KeyStoreAlias for " + sd.getName() + "; set 'KeyStoreAlias' in '"
                  + sd.getName() + "' security domain configuration");
         }

         Certificate cert = ts.getCertificate(alias);

         if (cert == null)
         {
            throw new LoginException("no certificate found for alias '" + alias + "' in the '" + sd.getName()
                  + "' security domain");
         }

         PublicKey publicKey = cert.getPublicKey();

         boolean sigValid = AssertionUtil.isSignatureValid(assertionElement, publicKey);
         if (!sigValid)
         {
            throw new LoginException(WSTrustConstants.STATUS_CODE_INVALID + " invalid SAML V2.0 assertion signature");
         }

         AssertionType assertion = SAMLUtil.fromElement(assertionElement);

         if (AssertionUtil.hasExpired(assertion))
         {
            throw new LoginException(WSTrustConstants.STATUS_CODE_INVALID
                  + "::assertion expired or used before its lifetime period");
         }
      }
      catch (NamingException e)
      {
         throw new LoginException(e.toString());
      }
      return true;
   }
}