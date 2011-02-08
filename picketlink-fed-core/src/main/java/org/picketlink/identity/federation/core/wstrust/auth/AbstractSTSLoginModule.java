/*
 * JBoss, Home of Professional Open Source Copyright 2009, Red Hat Middleware
 * LLC, and individual contributors by the @authors tag. See the copyright.txt
 * in the distribution for a full listing of individual contributors.
 * 
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 * 
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA, or see the FSF
 * site: http://www.fsf.org.
 */
package org.picketlink.identity.federation.core.wstrust.auth;

import java.io.IOException;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import javax.xml.datatype.XMLGregorianCalendar;

import org.apache.log4j.Logger;
import org.jboss.security.SecurityConstants;
import org.jboss.security.SecurityContext;
import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.identity.Role;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.mapping.MappingContext;
import org.jboss.security.mapping.MappingManager;
import org.jboss.security.mapping.MappingType;
import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.factories.JBossAuthCacheInvalidationFactory;
import org.picketlink.identity.federation.core.factories.JBossAuthCacheInvalidationFactory.TimeCacheExpiry;
import org.picketlink.identity.federation.core.saml.v2.util.AssertionUtil;
import org.picketlink.identity.federation.core.wstrust.STSClient;
import org.picketlink.identity.federation.core.wstrust.STSClientConfig;
import org.picketlink.identity.federation.core.wstrust.STSClientConfig.Builder;
import org.picketlink.identity.federation.core.wstrust.STSClientFactory;
import org.picketlink.identity.federation.core.wstrust.SamlCredential;
import org.picketlink.identity.federation.core.wstrust.WSTrustException;
import org.picketlink.identity.federation.core.wstrust.plugins.saml.SAMLUtil;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AssertionType;
import org.w3c.dom.Element;

/**
 * Abstract JAAS LoginModule for JBoss STS (Security Token Service).
 * </p> 
 * 
 * Subclasses are required to implement {@link #invokeSTS(STSClient)()} to perform their specific actions.
 * 
 * <h3>Configuration</h3>
 * Concrete implementations specify from where the username and credentials should be read from.
 * <lu>
 * <li>Callback handler, {@link NameCallback} and {@link PasswordCallback}.</li>
 * <li>From the login modules options configuration.</li>
 * <li>From the login modules earlier in the login modules stack.</li>
 * </lu>
 * 
 * <h3>Configuration example</h3>
 * 1. Callbackhandler configuration:
 * <pre>{@code
 * <application-policy name="saml-issue-token">
 *   <authentication>
 *     <login-module code="org.picketlink.identity.federation.core.wstrust.auth.STSIssuingLoginModule" flag="required">
 *       <module-option name="configFile">/sts-client.properties</module-option>
 *     </login-module>
 *   </authentication>
 * </application-policy>
 * }
 * </pre>
 * 2. Login module options configuration: 
 * <pre>{@code
 * <application-policy name="saml-issue-token">
 *   <authentication>
 *     <login-module code="org.picketlink.identity.federation.core.wstrust.auth.STSIssuingLoginModule" flag="required">
 *       <module-option name="configFile">/sts-client.properties</module-option>
 *       <module-option name="useOptionsCredentials">true</module-option>
 *     </login-module>
 *   </authentication>
 * </application-policy>
 * }
 * </pre>
 * 3. Password stacking configuration:
 * <pre>{@code
 * <application-policy name="saml-issue-token">
 *   <authentication>
 *     <login-module code="org.picketlink.identity.federation.core.wstrust.auth.STSIssuingLoginModule" flag="required">
 *       <module-option name="configFile">/sts-client.properties</module-option>
 *       <module-option name="password-stacking">useFirstPass</module-option>
 *     </login-module>
 *   </authentication>
 * </application-policy>
 * }
 * </pre>
 * 
 * <h3>Password stacking</h3>
 * Password stacking can be configured which means that a Login module configured with 'password-stacking' set to 'true'
 * will set the username and password in the shared state map. Login modules that come after can set 'password-stacking'
 * to 'useFirstPass' which means that that login module will use the username and password from the shared map.
 * <p/>
 * </pre>
 * 4. Mapping Provider configuration:
 * <pre>{@code
 * <application-policy name="saml-issue-token">
 *   <authentication>
 *     <login-module code="org.picketlink.identity.federation.core.wstrust.auth.STSIssuingLoginModule" flag="required">
 *       <module-option name="configFile">/sts-client.properties</module-option>
 *       <module-option name="password-stacking">useFirstPass</module-option>
 *     </login-module>
 *     <mapping>
 *       <mapping-module code="org.picketlink.identity.federation.bindings.jboss.auth.mapping.STSPrincipalMappingProvider" type="principal"/>
 *       <mapping-module code="org.picketlink.identity.federation.bindings.jboss.auth.mapping.STSGroupMappingProvider" type="role"/>
 *     </mapping>
 *   </authentication>
 * </application-policy>
 * }
 * </pre>
 * 
 * <h3>Mapping Providers</h3>
 * Principal and Role mapping providers may be configured on subclasses of this login module and be leveraged to
 * populate the JAAS Subject with appropriate user id and roles. The token is made available to the mapping providers
 * so that identity information may be extracted.
 * <p/>
 * 
 * Subclasses can define more configuration options by overriding initialize.
 * Also note that subclasses are not forced to put configuration options in a file. They
 * can all be set as options just like the 'configFile' is specified above.
 * 
 * <h3>Additional Configuration</h3>
 * <p>
 * groupPrincipalName: If you want the group principal in the subject representing the subject roles to have a name that is different
 *                     from "Roles".
 * </p>
 * 
 * <p>cache.invalidation:  set it to true if you require invalidation of JBoss Auth Cache at SAML Principal expiration.</p>
 *  <p>jboss.security.security_domain: name of the security domain where this login module is configured. This is only required
 *  if the cache.invalidation option is configured.</p>
 * 
 * @author <a href="mailto:dbevenius@jboss.com">Daniel Bevenius</a>
 * @author Anil.Saldhana@redhat.com
 */
public abstract class AbstractSTSLoginModule implements LoginModule
{
   private Logger log = Logger.getLogger(AbstractSTSLoginModule.class);

   /**
    * Key used in share state map when LMs are stacked. 
    */
   public static final String SHARED_TOKEN = "org.picketlink.identity.federation.core.wstrust.lm.stsToken";

   /**
    * Options configuration name;
    */
   public static final String OPTIONS_CREDENTIALS = "useOptionsCredentials";

   /**
    * Options configuration name;
    */
   public static final String OPTIONS_PW_STACKING = "password-stacking";

   /**
    * This is the required option that should identify the configuration
    * file for WSTrustClient. 
    */
   public static final String STS_CONFIG_FILE = "configFile";
   
   /**
    * Historically, JBoss has used the "Roles" as the group principal name in the subject
    * to represent the subject roles. Users can customize this name with this option.
    */
   public static final String GROUP_PRINCIPAL_NAME = "groupPrincipalName";

   /**
    * The subject to be populated.
    */
   protected Subject subject;

   /**
    * Callback handler used to gather information from the caller.
    */
   protected CallbackHandler callbackHandler;

   /**
    * WS-Trust SAML Assertion element.
    */
   protected Element samlToken;

   /**
    * The outcome of the authentication process.
    */
   protected boolean success;

   /**
    * The options map passed into this login modules initalize method.
    */
   protected Map<String, ?> options;

   /**
    * The shared state map passed into this login modules initalize method.
    */
   protected Map<String, ?> sharedState;

   /**
    * Indicates whether password stacking option was configured.
    */
   protected boolean passwordStacking;

   /**
    * Indicates whether the password-stacking options was specifed as 'useFirstPass'.
    */
   protected boolean useFirstPass;

   /**
    * Indicates whether the 'useOptionsCredentials' was configured.
    */
   protected boolean useOptionsCredentials;
   
   /**
    * Name of the group principal. If unconfigured, will be "null"
    */
   protected String groupPrincipalName = null; 
   
   protected boolean enableCacheInvalidation = false;
   
   protected String securityDomain = null;

   /**
    * Initialized this login module. Simple stores the passed in fields and
    * also validates the options.
    * 
    * @param subject
    *            The subject to authenticate/populate.
    * @param callbackHandler
    *            The callbackhandler that will gather information required by
    *            this login module.
    * @param sharedState
    *            State that is shared with other login modules. Used when
    *            modules are chained/stacked.
    * @param options
    *            The options that were specified for this login module.
    */
   public void initialize(final Subject subject, final CallbackHandler callbackHandler,
         final Map<String, ?> sharedState, final Map<String, ?> options)
   {
      this.subject = subject;
      this.callbackHandler = callbackHandler;
      this.options = options;
      this.sharedState = sharedState;

      final String pwStackingOption = (String) options.get(OPTIONS_PW_STACKING);
      passwordStacking = pwStackingOption != null;
      if (passwordStacking)
         useFirstPass = "useFirstPass".equals(pwStackingOption);

      final Boolean useOptionsCreds = Boolean.valueOf((String) options.get(OPTIONS_CREDENTIALS));
      if (useOptionsCreds != null)
         useOptionsCredentials = useOptionsCreds.booleanValue();
      
      final String gpPrincipalName = (String) options.get( GROUP_PRINCIPAL_NAME );
      if( gpPrincipalName != null && gpPrincipalName.length() > 0 )
         groupPrincipalName = gpPrincipalName;
      
      String cacheInvalidation = (String) options.get( "cache.invalidation" );
      if( cacheInvalidation != null && !cacheInvalidation.isEmpty() )
      {
         enableCacheInvalidation = Boolean.parseBoolean( cacheInvalidation );
         securityDomain = (String) options.get( SecurityConstants.SECURITY_DOMAIN_OPTION );
         if( securityDomain == null || securityDomain.isEmpty() )
            throw new RuntimeException( "Please configure option:" + SecurityConstants.SECURITY_DOMAIN_OPTION );
      }
   }

   /**
    * Subclasses must implement the login to perform their specific tasks. 
    * 
    * The login module should call {@link #setSamlToken(Element)} with the saml token
    * element that should be added to the public credentials in {@link #commit()}.
    * 
    * @return true If the login was successful otherwise false.
    * @throws LoginException If an error occurs while trying to perform the authentication.
    */
   public boolean login() throws LoginException
   {
      try
      {
         final Builder builder = new STSClientConfig.Builder(getRequiredOption(getOptions(), STS_CONFIG_FILE));
         if (useOptionsCredentials)
         {
            useCredentialsFromOptions(builder, options);
         }
         else if (isUseFirstPass())
         {
            useCredentialsFromSharedState(builder);
         }
         else
         {
            useCredentialsFromCallback(builder);
         }

         if (passwordStacking)
            setPasswordStackingCredentials(builder);

         final STSClient stsClient = createWSTrustClient(builder.build());

         final Element token = invokeSTS(stsClient);

         if (token == null)
         {
            // Throw an exception as returing false only says that this login module should be ignored.
            throw new LoginException("Could not issue a SAML Security Token");
         }
         setSuccess(true);
         setSamlToken(token);
         setSharedToken(token);
         return true;
      }
      catch (WSTrustException e)
      {
         throw new LoginException("WSTrustException : " + e.getMessage());
      }
   }

   public abstract Element invokeSTS(final STSClient stsclient) throws WSTrustException, LoginException;

   /**
    * Commit will package the samlToken set by the login method in a new {@link SamlCredential}.
    * This new SamlCredential will be put into the Subject public credentials set.
    */
   public boolean commit() throws LoginException
   {
      if (success)
      {
         final SamlCredential samlCredential = new SamlCredential(samlToken);
         final boolean added = subject.getPublicCredentials().add(samlCredential);
         populateSubject();
         if (added && log.isDebugEnabled())
            log.debug("Added Credential :" + samlCredential);

         return true;
      }
      else
      {
         return false;
      }
   }

   /**
    * Called if the overall authentication failed (phase 2).
    */
   public boolean abort() throws LoginException
   {
      success = false;
      clearState();
      return true;
   }

   public boolean logout() throws LoginException
   {
      clearState();
      return true;
   }

   protected void useCredentialsFromCallback(final Builder builder) throws LoginException
   {
      final NameCallback nameCallback = new NameCallback("user:");
      final PasswordCallback passwordCallback = new PasswordCallback("password:", true);
      try
      {
         getCallbackHandler().handle(new Callback[]
         {nameCallback, passwordCallback});
         builder.username(nameCallback.getName()).password(new String(passwordCallback.getPassword()));
      }
      catch (final IOException e)
      {
         throw new LoginException(e.getMessage());
      }
      catch (final UnsupportedCallbackException e)
      {
         throw new LoginException(e.getMessage());
      }
   }

   @SuppressWarnings({"rawtypes", "unchecked"})
   private void setPasswordStackingCredentials(final Builder builder)
   {
      final Map sharedState = (Map) this.sharedState;
      sharedState.put("javax.security.auth.login.name", builder.getUsername());
      sharedState.put("javax.security.auth.login.password", builder.getPassword());
   }

   protected void useCredentialsFromSharedState(final Builder builder)
   {
      builder.username(getSharedUsername()).password(new String(getSharedPassword()));
   }

   /**
    * This method allows subclassed to retreive configuration options map
    * and set on the builder. 
    * 
    * @param builder
    * @param options
    */
   protected void useCredentialsFromOptions(Builder builder, Map<String, ?> options2)
   {
      // NoOp. 
   }

   /**
    * This method gives users a chance to override how the {@link STSClientConfig} is created.
    * For example some users might perfer to not use a file containing the configuration 
    * properties, which is the default, but instead have the configuration options in the
    * login modules configuration directly.
    * 
    * @param options The options passed to the initialize method.
    * @return {@link STSClientConfig} The configuration for STSClient.
    */
   protected STSClientConfig getConfiguration(final Map<String, ?> options)
   {
      final String configFile = getRequiredOption(options, STS_CONFIG_FILE);
      return new STSClientConfig.Builder(configFile).build();
   }

   protected STSClient createWSTrustClient(final STSClientConfig config)
   {
      try
      {
         return STSClientFactory.getInstance().create(config);
      }
      catch (final ParsingException e)
      {
         throw new IllegalStateException("Could not create WSTrustClient:", e);
      }
   }

   protected String getRequiredOption(final Map<String, ?> options, final String optionName)
   {
      final String option = (String) options.get(optionName);
      if (option == null)
         throw new IllegalArgumentException("Required option '" + optionName
               + "' was missing from the login modules configuration");

      return option;
   }

   protected boolean isSuccess()
   {
      return success;
   }

   protected void setSuccess(boolean success)
   {
      this.success = success;
   }

   protected Subject getSubject()
   {
      return subject;
   }

   protected CallbackHandler getCallbackHandler()
   {
      return callbackHandler;
   }

   protected void setSamlToken(final Element samlToken)
   {
      this.samlToken = samlToken;
   }

   @SuppressWarnings({"unchecked", "rawtypes"})
   protected void setSharedToken(final Object token)
   {
      if (sharedState == null)
         return;
      /*
       * This is hidious but must be done since the signature of initialize in LoginModule is:
       * public void initialize(final Subject subject, final CallbackHandler callbackHandler, final Map<String, ?> sharedState, final Map<String, ?> options)
       * Notice how sharedState is defined. This means that it will not be possible to put anything into that map
       * without bypassing generics. 
       */
      // Cast the shartState to a raw map
      final Map state = (Map) sharedState;
      // Put the Token into the shared state map
      state.put(SHARED_TOKEN, token);
   }

   /**
    * Gets Security Token from the share state map if one was made available by
    * a previous LM in the stack.
    * 
    * @return Object A security token if one was stored in the shared state map. Or null if one does not exist.
    */
   protected Object getSharedToken()
   {
      if (sharedState == null)
         return null;

      return sharedState.get(SHARED_TOKEN);
   }

   /**
    * Gets the options provided to this LM in it's {@link #initialize(Subject, CallbackHandler, Map, Map)}.
    * 
    * @return Map<String, ?> The options map.
    */
   protected Map<String, ?> getOptions()
   {
      return options;
   }

   protected String getSharedUsername()
   {
      if (sharedState == null)
         return null;

      return (String) sharedState.get("javax.security.auth.login.name");
   }

   protected char[] getSharedPassword()
   {
      if (sharedState == null)
         return null;

      final Object object = sharedState.get("javax.security.auth.login.password");
      if (object instanceof char[])
         return (char[]) object;
      else if (object instanceof String)
         return ((String) object).toCharArray();

      return null;
   }

   protected boolean isUseFirstPass()
   {
      return useFirstPass;
   }

   protected boolean isUsePasswordStacking()
   {
      return passwordStacking;
   }

   protected boolean isUseOptionsConfig()
   {
      return useOptionsCredentials;
   }

   private void clearState()
   {
      removeAllSamlCredentials(subject);
      samlToken = null;
   }

   private void removeAllSamlCredentials(final Subject subject)
   {
      final Set<SamlCredential> samlCredentials = subject.getPublicCredentials(SamlCredential.class);
      if (!samlCredentials.isEmpty())
      {
         subject.getPublicCredentials().removeAll(samlCredentials);
      }
   }

   protected void populateSubject()
   {
      MappingManager mappingManager = getMappingManager();
      if (mappingManager == null)
      {
         return;
      }

      MappingContext<Principal> principalMappingContext = mappingManager.getMappingContext(MappingType.PRINCIPAL
            .toString());
      MappingContext<RoleGroup> roleMappingContext = mappingManager.getMappingContext(MappingType.ROLE.toString());

      Map<String, Object> contextMap = new HashMap<String, Object>();
      contextMap.put(SHARED_TOKEN, this.samlToken);

      if (principalMappingContext != null)
      {
         principalMappingContext.performMapping(contextMap, null);
         Principal principal = principalMappingContext.getMappingResult().getMappedObject();
         subject.getPrincipals().add(principal);
         
         //If the user has configured cache invalidation of subject based on saml token expiry
         if( enableCacheInvalidation )
         {
            TimeCacheExpiry cacheExpiry = JBossAuthCacheInvalidationFactory.getCacheExpiry();
            AssertionType assertion = null;
            try
            {
               assertion = SAMLUtil.fromElement( samlToken );
            }
            catch ( Exception e)
            {
               throw new RuntimeException( e );
            } 
            XMLGregorianCalendar expiry = AssertionUtil.getExpiration( assertion );
            if( expiry != null )
            {
               cacheExpiry.register( securityDomain, expiry.toGregorianCalendar().getTime() , principal );
            } 
            else
            {
               log.warn( "SAML Assertion has been found to have no expiration: ID = " + assertion.getID() );
            }
         }
      }

      if (roleMappingContext != null)
      {
         roleMappingContext.performMapping(contextMap, null);
         RoleGroup group = roleMappingContext.getMappingResult().getMappedObject();
         
         SimpleGroup rolePrincipal = null;
         
         if( groupPrincipalName != null )
         {
            rolePrincipal = new SimpleGroup( groupPrincipalName );
         }
         else
         {
            rolePrincipal= new SimpleGroup( group.getRoleName() ); 
         }
         
         for (Role role : group.getRoles())
         {
            rolePrincipal.addMember(new SimplePrincipal(role.getRoleName()));
         }
         subject.getPrincipals().add(rolePrincipal);
      }
   }

   protected MappingManager getMappingManager()
   {
      SecurityContext securityContext = SecurityActions.getSecurityContext();
      if (securityContext == null)
      {
         return null;
      }
      else
      {
         return securityContext.getMappingManager();
      }
   }
}