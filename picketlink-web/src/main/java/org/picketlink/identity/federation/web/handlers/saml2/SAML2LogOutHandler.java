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
package org.picketlink.identity.federation.web.handlers.saml2;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.log4j.Logger;
import org.picketlink.identity.federation.api.saml.v2.request.SAML2Request;
import org.picketlink.identity.federation.api.saml.v2.response.SAML2Response;
import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.saml.v2.common.IDGenerator;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLConstants;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2Handler;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerRequest;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerRequest.GENERATE_REQUEST_TYPE;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerResponse;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.saml.v2.SAML2Object;
import org.picketlink.identity.federation.saml.v2.protocol.LogoutRequestType;
import org.picketlink.identity.federation.saml.v2.protocol.ObjectFactory;
import org.picketlink.identity.federation.saml.v2.protocol.RequestAbstractType;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusCodeType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusResponseType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusType;
import org.picketlink.identity.federation.web.constants.GeneralConstants;
import org.picketlink.identity.federation.web.core.HTTPContext;
import org.picketlink.identity.federation.web.core.IdentityServer;

/**
 * SAML2 LogOut Profile
 * @author Anil.Saldhana@redhat.com
 * @since Sep 17, 2009
 */
public class SAML2LogOutHandler extends BaseSAML2Handler
{  
   private static Logger log = Logger.getLogger(SAML2LogOutHandler.class);
   private boolean trace = log.isTraceEnabled();
   
   private IDPLogOutHandler idp = new IDPLogOutHandler();
   private SPLogOutHandler sp = new SPLogOutHandler(); 
   
   private ObjectFactory objectFactory = new ObjectFactory();
   
   /**
    * @see SAML2Handler#generateSAMLRequest(SAML2HandlerRequest, SAML2HandlerResponse)
    */
   public void generateSAMLRequest(SAML2HandlerRequest request, SAML2HandlerResponse response)
         throws ProcessingException
   {
      if(request.getTypeOfRequestToBeGenerated() == null)
      {
         if(trace)
         {
            log.trace("Request type to be generated=null");
         }
         return;
      }
      if(GENERATE_REQUEST_TYPE.LOGOUT != request.getTypeOfRequestToBeGenerated())
         return;
      
      
      if(getType() == HANDLER_TYPE.IDP)
      {
         idp.generateSAMLRequest(request, response);
      }
      else
      {
         sp.generateSAMLRequest(request, response);
      }
   }
   
   /**
    * @see SAML2Handler#handleRequestType(RequestAbstractType)
    */
   public void handleRequestType(SAML2HandlerRequest request, 
         SAML2HandlerResponse response) throws ProcessingException
   { 
      if(request.getSAML2Object() instanceof LogoutRequestType == false)
         return ;
      
      if(getType() == HANDLER_TYPE.IDP)
      {
         idp.handleRequestType(request, response);
      }
      else
      {
         sp.handleRequestType(request, response);
      } 
   }

   /**
    * @see SAML2Handler#handleStatusResponseType(StatusResponseType,
         Document resultingDocument)
    */
   public void handleStatusResponseType(SAML2HandlerRequest request, 
         SAML2HandlerResponse response) throws ProcessingException
   {
      //we do not handle any ResponseType (authentication etc)
      if(request.getSAML2Object() instanceof ResponseType)
         return;
         
      if(request.getSAML2Object() instanceof StatusResponseType == false)
         return ;
      
      if(getType() == HANDLER_TYPE.IDP)
      {
         idp.handleStatusResponseType(request, response);
      }
      else
      {
         sp.handleStatusResponseType(request, response);
      } 
   }
   
   private class IDPLogOutHandler
   {
      public void generateSAMLRequest(SAML2HandlerRequest request, 
            SAML2HandlerResponse response) throws ProcessingException
      {
         
      }
      
      
      public void handleStatusResponseType( SAML2HandlerRequest request, 
             SAML2HandlerResponse response ) throws ProcessingException
      {  
         //we got a logout response from a SP
         SAML2Object samlObject = request.getSAML2Object();
         StatusResponseType statusResponseType = (StatusResponseType) samlObject;
         
         HTTPContext httpContext = (HTTPContext) request.getContext();
         HttpServletRequest httpRequest = httpContext.getRequest();
         HttpSession httpSession = httpRequest.getSession(false);
         
         String relayState = request.getRelayState();
         
         ServletContext servletCtx = httpContext.getServletContext();
         IdentityServer server = (IdentityServer)servletCtx.getAttribute("IDENTITY_SERVER");
         
         if(server == null)
            throw new ProcessingException("Identity Server not found");
         
         String sessionID = httpSession.getId();
         
         String statusIssuer = statusResponseType.getIssuer().getValue();
         server.stack().deRegisterTransitParticipant(sessionID, statusIssuer);
         
         String nextParticipant = this.getParticipant(server, sessionID, relayState);
         if(nextParticipant == null || nextParticipant.equals(relayState))
         {
            //we are done with logout
            
            //TODO: check the in transit map for partial logouts

            try
            {
               generateSuccessStatusResponseType(statusResponseType.getInResponseTo(),
                     request, response, relayState);
               Boolean isPost = server.stack().getBinding( relayState );
               if( isPost == null )
                  isPost = Boolean.TRUE;
               response.setPostBindingForResponse( isPost.booleanValue() );
            }
            catch (Exception e)
            {
               throw new ProcessingException(e);
            }
            
            httpSession.invalidate(); //We are done with the logout interaction
         }
         else
         {
            //Put the participant in transit mode
            server.stack().registerTransitParticipant(sessionID, nextParticipant);
            Boolean isPost = server.stack().getBinding( nextParticipant );
            if( isPost == null )
               isPost = Boolean.TRUE;
            response.setPostBindingForResponse( isPost.booleanValue() );
            
            //send logout request to participant with relaystate to orig
            response.setRelayState(relayState);
            
            response.setDestination(nextParticipant);
            
            SAML2Request saml2Request = new SAML2Request();
            try
            {
               LogoutRequestType lort = saml2Request.createLogoutRequest(request.getIssuer().getValue());
               response.setResultingDocument(saml2Request.convert(lort)); 
               response.setSendRequest(true);
            }
            catch(Exception e)
            {
               throw new ProcessingException(e);
            }
         }
      }
      
      public void handleRequestType( SAML2HandlerRequest request, 
            SAML2HandlerResponse response ) throws ProcessingException
      {
         HTTPContext httpContext = (HTTPContext) request.getContext();
         HttpSession session = httpContext.getRequest().getSession(false);
         String sessionID = session.getId();
         
         String relayState = httpContext.getRequest().getParameter(GeneralConstants.RELAY_STATE);
         
         LogoutRequestType logOutRequest = (LogoutRequestType) request.getSAML2Object();
         String issuer = logOutRequest.getIssuer().getValue();
         try
         { 
            SAML2Request saml2Request = new SAML2Request();
            
            ServletContext servletCtx = httpContext.getServletContext();
            IdentityServer server = (IdentityServer)servletCtx.getAttribute(GeneralConstants.IDENTITY_SERVER);
            
            if(server == null)
               throw new ProcessingException("Identity Server not found");
            
            String originalIssuer = (relayState == null) ? issuer : relayState;
            
            String participant = this.getParticipant(server, sessionID, originalIssuer);
           
            if(participant == null || participant.equals(originalIssuer))
            {
               //All log out is done
               session.invalidate();
               server.stack().pop(sessionID);
               
               Boolean isPost = server.stack().getBinding( participant );
               if( isPost == null )
                  isPost = Boolean.TRUE;
               
               generateSuccessStatusResponseType(logOutRequest.getID(),
                     request, response, originalIssuer);
               response.setPostBindingForResponse( isPost.booleanValue() );
               response.setSendRequest(false);
            }
            else
            {
               //Put the participant in transit mode
               server.stack().registerTransitParticipant(sessionID, participant);
               
               if(relayState == null)
                  relayState = originalIssuer;
               
               //send logout request to participant with relaystate to orig
               response.setRelayState(originalIssuer);
               
               response.setDestination(participant);
               
               Boolean isPost = server.stack().getBinding(participant);
               if( isPost == null )
                  isPost = Boolean.TRUE;
               
               response.setPostBindingForResponse( isPost );
               
               
               LogoutRequestType lort = saml2Request.createLogoutRequest(request.getIssuer().getValue());

               long assertionValidity = (Long) request.getOptions().get(GeneralConstants.ASSERTIONS_VALIDITY);
               
               lort.setNotOnOrAfter(XMLTimeUtil.add(lort.getIssueInstant(), assertionValidity));
               lort.setDestination(participant);
               
               response.setResultingDocument(saml2Request.convert(lort));
               response.setSendRequest(true);
            }
         }
         catch(ParserConfigurationException pe)
         {
            throw new ProcessingException(pe);
         }
         catch(ConfigurationException pe)
         {
            throw new ProcessingException(pe);
         }
         catch (ParsingException e)
         {
            throw new ProcessingException( e );
         }
         /*catch(JAXBException pe)
         {
            throw new ProcessingException(pe);
         }
         catch(IOException pe)
         {
            throw new ProcessingException(pe);
         }
         catch(SAXException pe)
         {
            throw new ProcessingException(pe);
         }*/
         return;
      }


      private void generateSuccessStatusResponseType(
            String logOutRequestID,
            SAML2HandlerRequest request, 
            SAML2HandlerResponse response,
            String originalIssuer)
            throws ConfigurationException, ParserConfigurationException, ProcessingException
      { 
         StatusResponseType statusResponse = objectFactory.createStatusResponseType();
         
         //Status
         StatusType statusType = objectFactory.createStatusType();
         StatusCodeType statusCodeType = objectFactory.createStatusCodeType();
         statusCodeType.setValue(JBossSAMLURIConstants.STATUS_RESPONDER.get());
         
         //2nd level status code
         StatusCodeType status2ndLevel = objectFactory.createStatusCodeType();
         status2ndLevel.setValue(JBossSAMLURIConstants.STATUS_SUCCESS.get());
         statusCodeType.setStatusCode(status2ndLevel);
         
         statusType.setStatusCode(statusCodeType);
         
         statusResponse.setStatus(statusType);
         
         statusResponse.setIssueInstant(XMLTimeUtil.getIssueInstant());
         statusResponse.setInResponseTo(logOutRequestID);
         statusResponse.setID(IDGenerator.create("ID_"));
         statusResponse.setVersion( JBossSAMLConstants.VERSION_2_0.get() );
         
         statusResponse.setIssuer(request.getIssuer());
         
         try
         {
            SAML2Response saml2Response = new SAML2Response();
            response.setResultingDocument(saml2Response.convert(statusResponse)); 
         } 
         catch( ParsingException je)
         {
            throw new ProcessingException(je);
         }
         
         response.setDestination(originalIssuer);
      }
      
      private String getParticipant(IdentityServer server, String sessionID,
            String originalRequestor)
      {
         int participants = server.stack().getParticipants(sessionID);
         
         String participant = originalRequestor;
         //Get a participant who is not equal to the original issuer of the logout request
         if(participants > 0)
         {
            do
            {
               participant = server.stack().pop(sessionID); 
               --participants;   
            }
            while(participants > 0 && participant.equals(originalRequestor));
         }
         
        return participant; 
      }
   }
   
   private class SPLogOutHandler
   {
      public void generateSAMLRequest(SAML2HandlerRequest request, 
            SAML2HandlerResponse response) throws ProcessingException
      {
         //Generate the LogOut Request
         SAML2Request samlRequest = new SAML2Request();
         try
         {
            LogoutRequestType lot = 
               samlRequest.createLogoutRequest(request.getIssuer().getValue());
            
            response.setResultingDocument(samlRequest.convert(lot));
            response.setSendRequest(true);
         }
         catch (Exception e)
         {
            throw new ProcessingException(e);
         } 
      }
      
      public void handleStatusResponseType( SAML2HandlerRequest request, 
            SAML2HandlerResponse response ) throws ProcessingException
      { 
         //Handler a log out response from IDP
         StatusResponseType statusResponseType = (StatusResponseType) request.getSAML2Object();
         
         HTTPContext httpContext = (HTTPContext) request.getContext();
         HttpServletRequest servletRequest = httpContext.getRequest();
         HttpSession session = servletRequest.getSession(false);
         
         //TODO: Deal with partial logout report
         
         StatusType statusType = statusResponseType.getStatus();
         StatusCodeType statusCode = statusType.getStatusCode();
         StatusCodeType secondLevelstatusCode = statusCode.getStatusCode();
         if(secondLevelstatusCode.getValue().equals(JBossSAMLURIConstants.STATUS_SUCCESS.get()))
         {
            //we are successfully logged out
            session.invalidate();
         } 
      }
      
      public void handleRequestType( SAML2HandlerRequest request,  
            SAML2HandlerResponse response ) throws ProcessingException
      {  
         SAML2Object samlObject = request.getSAML2Object();
         if(samlObject instanceof LogoutRequestType == false)
            return;
         
         LogoutRequestType logOutRequest = (LogoutRequestType) samlObject;
         HTTPContext httpContext = (HTTPContext) request.getContext();
         HttpServletRequest servletRequest = httpContext.getRequest();
         HttpSession session = servletRequest.getSession(false);
         
         String relayState = servletRequest.getParameter("RelayState");
         
         session.invalidate(); //Invalidate the current session at the SP
         
         //Generate a Logout Response
         StatusResponseType statusResponse = objectFactory.createStatusResponseType();
         
         //Status
         StatusType statusType = objectFactory.createStatusType();
         StatusCodeType statusCodeType = objectFactory.createStatusCodeType();
         statusCodeType.setValue(JBossSAMLURIConstants.STATUS_RESPONDER.get());
         
         //2nd level status code
         StatusCodeType status2ndLevel = objectFactory.createStatusCodeType();
         status2ndLevel.setValue(JBossSAMLURIConstants.STATUS_SUCCESS.get());
         statusCodeType.setStatusCode(status2ndLevel);
         
         statusType.setStatusCode(statusCodeType);
         
         statusResponse.setStatus(statusType);
         
         try
         {
            statusResponse.setIssueInstant(XMLTimeUtil.getIssueInstant());
         }
         catch (ConfigurationException e)
         {
            throw new ProcessingException(e);
         }
         statusResponse.setInResponseTo(logOutRequest.getID());
         statusResponse.setID(IDGenerator.create("ID_"));
         statusResponse.setVersion( JBossSAMLConstants.VERSION_2_0.get() );
         
         statusResponse.setIssuer(request.getIssuer());
         
         SAML2Response saml2Response = new SAML2Response();
         try
         {
            response.setResultingDocument(saml2Response.convert(statusResponse)); 
         } 
         catch(Exception je)
         {
            throw new ProcessingException(je);
         }
         
         response.setRelayState(relayState);
         response.setDestination(logOutRequest.getIssuer().getValue());
         response.setSendRequest(false);
      }
   } 
}