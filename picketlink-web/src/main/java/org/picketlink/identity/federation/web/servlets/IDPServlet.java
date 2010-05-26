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
package org.picketlink.identity.federation.web.servlets;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.picketlink.identity.federation.core.config.AuthPropertyType;
import org.picketlink.identity.federation.core.config.IDPType;
import org.picketlink.identity.federation.core.config.KeyProviderType;
import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.handler.config.Handlers;
import org.picketlink.identity.federation.core.impl.DelegatedAttributeManager;
import org.picketlink.identity.federation.core.interfaces.AttributeManager;
import org.picketlink.identity.federation.core.interfaces.ProtocolContext;
import org.picketlink.identity.federation.core.interfaces.RoleGenerator;
import org.picketlink.identity.federation.core.interfaces.TrustKeyConfigurationException;
import org.picketlink.identity.federation.core.interfaces.TrustKeyManager;
import org.picketlink.identity.federation.core.interfaces.TrustKeyProcessingException;
import org.picketlink.identity.federation.core.saml.v2.common.SAMLDocumentHolder;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.core.saml.v2.exceptions.IssueInstantMissingException;
import org.picketlink.identity.federation.core.saml.v2.exceptions.IssuerNotTrustedException;
import org.picketlink.identity.federation.core.saml.v2.holders.IssuerInfoHolder;
import org.picketlink.identity.federation.core.saml.v2.impl.DefaultSAML2HandlerChain;
import org.picketlink.identity.federation.core.saml.v2.impl.DefaultSAML2HandlerChainConfig;
import org.picketlink.identity.federation.core.saml.v2.impl.DefaultSAML2HandlerRequest;
import org.picketlink.identity.federation.core.saml.v2.impl.DefaultSAML2HandlerResponse;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2Handler;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerChain;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerChainConfig;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerRequest;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerResponse; 
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2Handler.HANDLER_TYPE;
import org.picketlink.identity.federation.core.saml.v2.util.HandlerUtil;
import org.picketlink.identity.federation.core.util.CoreConfigUtil;
import org.picketlink.identity.federation.saml.v2.SAML2Object;
import org.picketlink.identity.federation.saml.v2.protocol.RequestAbstractType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusResponseType;
import org.picketlink.identity.federation.web.constants.GeneralConstants;
import org.picketlink.identity.federation.web.core.HTTPContext;
import org.picketlink.identity.federation.web.core.IdentityServer;
import org.picketlink.identity.federation.web.roles.DefaultRoleGenerator;
import org.picketlink.identity.federation.web.util.ConfigurationUtil;
import org.picketlink.identity.federation.web.util.IDPWebRequestUtil;
import org.picketlink.identity.federation.web.util.RedirectBindingSignatureUtil;
import org.picketlink.identity.federation.web.util.IDPWebRequestUtil.WebRequestUtilHolder;
import org.w3c.dom.Document;


import static org.picketlink.identity.federation.core.util.StringUtil.isNotNull;

/**
 * SAML Web Browser SSO - POST binding
 * @author Anil.Saldhana@redhat.com
 * @since Aug 13, 2009
 */
public class IDPServlet extends HttpServlet
{
   private static final long serialVersionUID = 1L;
   private static Logger log = Logger.getLogger(IDPServlet.class);
   private boolean trace = log.isTraceEnabled();
   
   protected transient IDPType idpConfiguration = null;

   private transient RoleGenerator roleGenerator = new DefaultRoleGenerator();
   
   private transient DelegatedAttributeManager attribManager = new DelegatedAttributeManager();

   private List<String> attributeKeys = new ArrayList<String>();
   
   private long assertionValidity = 5000; // 5 seconds in miliseconds

   private String identityURL = null;

   private transient TrustKeyManager keyManager;

   private Boolean ignoreIncomingSignatures = false;

   private Boolean signOutgoingMessages = true; 
   
   private transient ServletContext context = null;
   
   private transient SAML2HandlerChain chain = null;

   public Boolean getIgnoreIncomingSignatures()
   {
      return ignoreIncomingSignatures;
   }
   
   @Override
   public void init(ServletConfig config) throws ServletException
   {
      Handlers handlers = null;
      super.init(config);
      String configFile = GeneralConstants.CONFIG_FILE_LOCATION;
      
      context = config.getServletContext();
      
      InputStream is = context.getResourceAsStream(configFile);
      if(is == null)
         throw new RuntimeException(configFile + " missing");

      //Get the chain from config
      chain = new DefaultSAML2HandlerChain();
      
      try
      {
         idpConfiguration = ConfigurationUtil.getIDPConfiguration(is);
         this.identityURL = idpConfiguration.getIdentityURL(); 
         log.trace("Identity Provider URL=" + this.identityURL); 
         this.assertionValidity = idpConfiguration.getAssertionValidity();
         
         //Get the attribute manager
         String attributeManager = idpConfiguration.getAttributeManager();
         if(attributeManager != null && !"".equals(attributeManager))
         {
            ClassLoader tcl = SecurityActions.getContextClassLoader();
            AttributeManager delegate = (AttributeManager) tcl.loadClass(attributeManager).newInstance();
            this.attribManager.setDelegate(delegate);
         }
         
         //Get the handlers
         String handlerConfigFileName = GeneralConstants.HANDLER_CONFIG_FILE_LOCATION;
         handlers = ConfigurationUtil.getHandlers(context.getResourceAsStream(handlerConfigFileName));
         chain.addAll(HandlerUtil.getHandlers(handlers)); 
         
         Map<String, Object> chainConfigOptions = new HashMap<String, Object>();
         chainConfigOptions.put(GeneralConstants.ROLE_GENERATOR, roleGenerator);
         chainConfigOptions.put(GeneralConstants.CONFIGURATION, idpConfiguration);
         
         SAML2HandlerChainConfig handlerChainConfig = new DefaultSAML2HandlerChainConfig(chainConfigOptions);
         Set<SAML2Handler> samlHandlers = chain.handlers();
         
         for(SAML2Handler handler: samlHandlers)
         {
            handler.initChainConfig(handlerChainConfig);
         } 
      }
      catch (Exception e)
      {
         throw new RuntimeException(e);
      }
      
      //Handle the sign outgoing messages
      String signOutgoingString = config.getInitParameter(GeneralConstants.SIGN_OUTGOING_MESSAGES);
      if(signOutgoingString != null && !"".equals(signOutgoingString))
         this.signOutgoingMessages = Boolean.parseBoolean(signOutgoingString);
      
      
      if(this.signOutgoingMessages)
      {
         KeyProviderType keyProvider = this.idpConfiguration.getKeyProvider();
         if(keyProvider == null)
            throw new RuntimeException("Key Provider is null for context=" + context.getContextPath());
         
         try
         {
            ClassLoader tcl = SecurityActions.getContextClassLoader();
            String keyManagerClassName = keyProvider.getClassName();
            if(keyManagerClassName == null)
               throw new RuntimeException("KeyManager class name is null");
            
            Class<?> clazz = tcl.loadClass(keyManagerClassName);
            this.keyManager = (TrustKeyManager) clazz.newInstance();
            
            List<AuthPropertyType> authProperties = CoreConfigUtil.getKeyProviderProperties(keyProvider);
            
            keyManager.setAuthProperties( authProperties );
            keyManager.setValidatingAlias(keyProvider.getValidatingAlias());
         }
         catch(Exception e)
         {
            log.error("Exception reading configuration:",e);
            throw new RuntimeException(e.getLocalizedMessage());
         }
         if(trace) 
            log.trace("Key Provider=" + keyProvider.getClassName()); 
      }
      
      //handle the role generator
      String rgString = config.getInitParameter(GeneralConstants.ROLE_GENERATOR);
      if(rgString != null && !"".equals(rgString))
         this.setRoleGenerator(rgString);
      
      //Get a list of attributes we are interested in
      String attribList = config.getInitParameter(GeneralConstants.ATTRIBUTE_KEYS);
      if(attribList != null && !"".equals(attribList))
      {
         StringTokenizer st = new StringTokenizer(attribList,",");
         while(st != null && st.hasMoreTokens())
         {
            this.attributeKeys.add(st.nextToken());
         }
      }  
      
      //The Identity Server on the servlet context gets set
      //in the implementation of IdentityServer
      //Create an Identity Server and set it on the context
      IdentityServer identityServer = (IdentityServer) context.getAttribute(GeneralConstants.IDENTITY_SERVER);
      if(identityServer == null)
      {
         identityServer = new IdentityServer();
         context.setAttribute(GeneralConstants.IDENTITY_SERVER, identityServer); 
      } 
   }   
   
   
   @SuppressWarnings("unchecked")
   @Override
   protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
   {
      //Some issue with filters and servlets
      HttpSession session = request.getSession(false); 
      
      String samlRequestMessage = (String) session.getAttribute(GeneralConstants.SAML_REQUEST_KEY);
      String samlResponseMessage = (String) session.getAttribute(GeneralConstants.SAML_RESPONSE_KEY);
      String relayState = (String) session.getAttribute(GeneralConstants.RELAY_STATE);
      
      String referer = request.getHeader("Referer"); 

      //See if the user has already been authenticated
      Principal userPrincipal = (Principal) session.getAttribute(GeneralConstants.PRINCIPAL_ID);

      if(userPrincipal == null)
      {
         //The sys admin has not set up the login servlet filters for the IDP
         if(trace) 
            log.trace("Login Filters have not been configured");
         response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR); 
      }      
      
      IDPWebRequestUtil webRequestUtil = new IDPWebRequestUtil(request, 
            idpConfiguration, keyManager);
      webRequestUtil.setAttributeManager(this.attribManager);
      webRequestUtil.setAttributeKeys(attributeKeys);

      boolean willSendRequest = true;
      
      if(userPrincipal != null)
      {
         if(trace)
         {
            log.trace("Retrieved saml message and relay state from session");
            log.trace("saml Request message=" + samlRequestMessage + "::relay state="+ relayState);
            log.trace("saml Response message=" + samlResponseMessage + "::relay state="+ relayState);
         }
         session.removeAttribute(GeneralConstants.SAML_REQUEST_KEY);
         session.removeAttribute(GeneralConstants.SAML_RESPONSE_KEY);

         if(isNotNull(relayState))
            session.removeAttribute(GeneralConstants.RELAY_STATE);
         
         SAMLDocumentHolder samlDocumentHolder = null;
         SAML2Object samlObject = null;
         String destination = null;
         Document samlResponse = null;
         
         if(samlResponseMessage != null)
         {
            StatusResponseType statusResponseType = null;
            try
            {
               samlDocumentHolder = webRequestUtil.getSAMLDocumentHolder(samlResponseMessage);
               samlObject = (SAML2Object) samlDocumentHolder.getSamlObject();
               
               boolean isPost = webRequestUtil.hasSAMLRequestInPostProfile();
               boolean isValid = validate(request.getRemoteAddr(),
                     request.getQueryString(),
                     new SessionHolder(samlResponseMessage, null), isPost);
               
               if(!isValid)
                  throw new GeneralSecurityException("Validation check failed");

               String issuer = null;
               IssuerInfoHolder idpIssuer = new IssuerInfoHolder(this.identityURL);
               ProtocolContext protocolContext = new HTTPContext(request,response, context);
               //Create the request/response
               SAML2HandlerRequest saml2HandlerRequest = 
                  new DefaultSAML2HandlerRequest(protocolContext,
                        idpIssuer.getIssuer(), samlDocumentHolder, 
                        HANDLER_TYPE.IDP);
               saml2HandlerRequest.setRelayState(relayState);
               
               SAML2HandlerResponse saml2HandlerResponse = new DefaultSAML2HandlerResponse(); 

               Set<SAML2Handler> handlers = chain.handlers();
               
               if(samlObject instanceof StatusResponseType)
               {
                  statusResponseType = (StatusResponseType) samlObject;
                  issuer = statusResponseType.getIssuer().getValue();
                  webRequestUtil.isTrusted(issuer);
                  
                  if(handlers != null)
                  { 
                     for(SAML2Handler handler: handlers)
                     {
                        handler.reset();
                        handler.handleStatusResponseType(saml2HandlerRequest, saml2HandlerResponse);
                        willSendRequest = saml2HandlerResponse.getSendRequest();
                     } 
                  }  
               }
               else
                  throw new RuntimeException("Unknown type:" + samlObject.getClass().getName());

               samlResponse = saml2HandlerResponse.getResultingDocument();
               relayState = saml2HandlerResponse.getRelayState();
               
               destination = saml2HandlerResponse.getDestination();
            }
            catch(Exception e)
            {
               throw new RuntimeException(e);
            }
              
         }
         else
         //Send valid saml response after processing the request
         if(samlRequestMessage != null)
         {
            //Get the SAML Request Message
            RequestAbstractType requestAbstractType =  null; 
            
            try
            { 
               samlDocumentHolder = webRequestUtil.getSAMLDocumentHolder(samlRequestMessage);
               samlObject = (SAML2Object) samlDocumentHolder.getSamlObject();
               
               
               boolean isPost = webRequestUtil.hasSAMLRequestInPostProfile();
               boolean isValid = validate(request.getRemoteAddr(),
                     request.getQueryString(),
                     new SessionHolder(samlRequestMessage, null), isPost);
               
               if(!isValid)
                  throw new GeneralSecurityException("Validation check failed");

               String issuer = null;
               IssuerInfoHolder idpIssuer = new IssuerInfoHolder(this.identityURL);
               ProtocolContext protocolContext = new HTTPContext(request,response, context);
               //Create the request/response
               SAML2HandlerRequest saml2HandlerRequest = 
                  new DefaultSAML2HandlerRequest(protocolContext,
                        idpIssuer.getIssuer(), samlDocumentHolder, 
                        HANDLER_TYPE.IDP);
               saml2HandlerRequest.setRelayState(relayState);
               
               //Set the options on the handler request
               Map<String, Object> requestOptions = new HashMap<String, Object>();
               requestOptions.put(GeneralConstants.ROLE_GENERATOR, roleGenerator);
               requestOptions.put(GeneralConstants.ASSERTIONS_VALIDITY, this.assertionValidity);
               requestOptions.put(GeneralConstants.CONFIGURATION, this.idpConfiguration);
               
               Map<String,Object> attribs  = this.attribManager.getAttributes(userPrincipal, attributeKeys);
               requestOptions.put(GeneralConstants.ATTRIBUTES, attribs);
               
               saml2HandlerRequest.setOptions(requestOptions); 
               
               List<String> roles = (List<String>) session.getAttribute(GeneralConstants.ROLES_ID); 
               if(roles == null) 
               {
                  roles = roleGenerator.generateRoles(userPrincipal);
                  session.setAttribute(GeneralConstants.ROLES_ID, roles);
               }
               
               SAML2HandlerResponse saml2HandlerResponse = new DefaultSAML2HandlerResponse(); 

               Set<SAML2Handler> handlers = chain.handlers();
               
               if(samlObject instanceof RequestAbstractType)
               {
                  requestAbstractType = (RequestAbstractType) samlObject;
                  issuer = requestAbstractType.getIssuer().getValue();
                  webRequestUtil.isTrusted(issuer);
                  
                  if(handlers != null)
                  { 
                     for(SAML2Handler handler: handlers)
                     {
                        handler.handleRequestType(saml2HandlerRequest, saml2HandlerResponse);
                        willSendRequest = saml2HandlerResponse.getSendRequest();
                     } 
                  } 
               } 
               else
                  throw new RuntimeException("Unknown type:" + samlObject.getClass().getName());

               samlResponse = saml2HandlerResponse.getResultingDocument();
               relayState = saml2HandlerResponse.getRelayState();
               
               destination = saml2HandlerResponse.getDestination();
                
            }
            catch (IssuerNotTrustedException e)
            {
               if(trace) log.trace("Exception:",e);

               samlResponse =
                  webRequestUtil.getErrorResponse(referer, 
                        JBossSAMLURIConstants.STATUS_REQUEST_DENIED.get(), 
                        this.identityURL, this.signOutgoingMessages);  
            }
            catch (ParsingException e)
            {
               if(trace) log.trace("Exception:",e);

               samlResponse =
                  webRequestUtil.getErrorResponse(referer, 
                        JBossSAMLURIConstants.STATUS_AUTHNFAILED.get(), 
                        this.identityURL, this.signOutgoingMessages); 
            }
            catch (ConfigurationException e)
            {
               if(trace) log.trace("Exception:",e); 

               samlResponse =
                  webRequestUtil.getErrorResponse(referer, 
                        JBossSAMLURIConstants.STATUS_AUTHNFAILED.get(), 
                        this.identityURL, this.signOutgoingMessages);
            }
            catch (IssueInstantMissingException e)
            {
               if(trace) log.trace("Exception:",e); 

               samlResponse =
                  webRequestUtil.getErrorResponse(referer, 
                        JBossSAMLURIConstants.STATUS_AUTHNFAILED.get(), 
                        this.identityURL, this.signOutgoingMessages); 
            } 
            catch(GeneralSecurityException e)
            {
               if(trace) log.trace("Security Exception:",e); 

               samlResponse =
                  webRequestUtil.getErrorResponse(referer, 
                        JBossSAMLURIConstants.STATUS_AUTHNFAILED.get(), 
                        this.identityURL, this.signOutgoingMessages); 
            }
            catch(Exception e)
            {
               if(trace) log.trace("Exception:",e); 

               samlResponse =
                  webRequestUtil.getErrorResponse(referer, 
                        JBossSAMLURIConstants.STATUS_AUTHNFAILED.get(), 
                        this.identityURL, this.signOutgoingMessages); 
            }
            
         }
         else
         {
            log.error("No SAML Request Message");
            if(trace) log.trace("Referer="+referer);

            try
            {
               sendErrorResponseToSP(referer, response, relayState, webRequestUtil);
               return;
            }
            catch (ConfigurationException e)
            {
               if(trace) log.trace(e);
            } 
         } 
         
         try
         { 
            if(samlResponse == null)
               throw new ServletException("SAML Response has not been generated");



            WebRequestUtilHolder holder = webRequestUtil.getHolder();
            holder.setResponseDoc(samlResponse).setDestination(destination).setRelayState(relayState).setAreWeSendingRequest( willSendRequest )
            .setPrivateKey(null).setSupportSignature(false).setServletResponse(response);
            holder.setPostBindingRequested(true);
            
            if(this.signOutgoingMessages)
            {
               holder.setPrivateKey( keyManager.getSigningKey() ).setSupportSignature(true);
               /*webRequestUtil.send(samlResponse, destination,relayState, response, true, 
                     this.keyManager.getSigningKey(), willSendRequest);*/
            }
            /*   
            else
               webRequestUtil.send(samlResponse, destination, relayState, response, false,null, willSendRequest);*/
            webRequestUtil.send(holder);
         }
         catch (ParsingException e)
         {
            if(trace) log.trace(e);
         } 
         catch (GeneralSecurityException e)
         {
            if(trace) log.trace(e);
         }

         return;
      } 
   }

   protected void sendErrorResponseToSP(String referrer, HttpServletResponse response, String relayState,
         IDPWebRequestUtil webRequestUtil) throws ServletException, IOException, ConfigurationException
   {
      if(trace) log.trace("About to send error response to SP:" + referrer);

      Document samlResponse =   
         webRequestUtil.getErrorResponse(referrer, JBossSAMLURIConstants.STATUS_RESPONDER.get(),
               this.identityURL, this.signOutgoingMessages);
      try
      {   
         WebRequestUtilHolder holder = webRequestUtil.getHolder();
         holder.setResponseDoc(samlResponse).setDestination(referrer).setRelayState(relayState).setAreWeSendingRequest( false )
         .setPrivateKey(null).setSupportSignature(false).setServletResponse(response);
         holder.setPostBindingRequested(true);
         
         if(this.signOutgoingMessages)
         {
            holder.setPrivateKey( keyManager.getSigningKey() ).setSupportSignature( true );
            /*webRequestUtil.send(samlResponse, referrer, relayState, response, true, 
                  this.keyManager.getSigningKey(), false);*/
         }
            
        /* else
            webRequestUtil.send(samlResponse, referrer, relayState, response, false,null, false);*/
         webRequestUtil.send(holder);
      }
      catch (ParsingException e1)
      {
         throw new ServletException(e1);
      }
      catch (GeneralSecurityException e)
      { 
         throw new ServletException(e);
      } 
   } 

   @Override
   protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException
   {
      resp.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
   }  
   

   protected static class SessionHolder
   {
      String samlRequest;
      String signature; 
      
      public SessionHolder(String req, String sig)
      {
         this.samlRequest = req;
         this.signature = sig; 
      }
   }
   
   protected boolean validate(String remoteAddress, 
         String queryString,
         SessionHolder holder, boolean isPost) throws IOException, GeneralSecurityException
   {   
      if (holder.samlRequest == null || holder.samlRequest.length() == 0)
      {
         return false;
      }

      if (!this.ignoreIncomingSignatures && !isPost)
      {
         String sig = holder.signature;
         if (sig == null || sig.length() == 0)
         {
            log.error("Signature received from SP is null:" + remoteAddress);
            return false;
         }
         
         //Check if there is a signature   
         byte[] sigValue = RedirectBindingSignatureUtil.getSignatureValueFromSignedURL(queryString);
         if(sigValue == null)
            return false;
         
         PublicKey validatingKey;
         try
         {
            validatingKey = keyManager.getValidatingKey(remoteAddress);
         }
         catch (TrustKeyConfigurationException e)
         {
            throw new GeneralSecurityException(e.getCause());
         }
         catch (TrustKeyProcessingException e)
         {
            throw new GeneralSecurityException(e.getCause());
         }
         
         return RedirectBindingSignatureUtil.validateSignature(queryString, validatingKey, sigValue);
      }
      else
      {
         //Post binding no signature verification. The SAML message signature is verified
         return true;
      }
   }
   
   public void testPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
   {
      this.doPost(request, response); 
   }
   
   private void setRoleGenerator(String rgName)
   {
      try
      {
         Class<?> clazz = SecurityActions.getContextClassLoader().loadClass(rgName);
         roleGenerator = (RoleGenerator) clazz.newInstance();
      }
      catch (Exception e)
      {
         throw new RuntimeException(e);
      } 
   }
}