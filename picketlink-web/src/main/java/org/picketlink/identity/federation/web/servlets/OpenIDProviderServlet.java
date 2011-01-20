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

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.openid4java.message.Parameter;
import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.openid.providers.helpers.OpenIDParameterList;
import org.picketlink.identity.federation.core.openid.providers.helpers.OpenIDProtocolContext;
import org.picketlink.identity.federation.core.openid.providers.helpers.OpenIDProtocolContext.AUTH_HOLDER;
import org.picketlink.identity.federation.core.openid.providers.helpers.OpenIDProtocolContext.MODE;
import org.picketlink.identity.federation.core.openid.providers.helpers.OpenIDProviderManager.OpenIDMessage;
import org.picketlink.identity.federation.core.sts.PicketLinkCoreSTS;

/**
 * Servlet that provides the Provider functionality
 * for OpenID
 * @author Anil.Saldhana@redhat.com
 * @since Jul 15, 2009
 */
public class OpenIDProviderServlet extends HttpServlet
{
   private static final long serialVersionUID = 1L;
   private transient ServletContext servletContext = null;
   private String securePageName = "securepage.jsp";
   
   private transient PicketLinkCoreSTS sts = PicketLinkCoreSTS.instance();

   @Override
   public void init(ServletConfig config) throws ServletException
   {
      super.init(config);
      this.servletContext = config.getServletContext();
      String secpageStr = this.servletContext.getInitParameter("securePage");
      if(secpageStr != null && secpageStr.length() > 0)
         securePageName = secpageStr;

      sts.installDefaultConfiguration( ( String[] )null ); 
   }

   @Override
   protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
   {
      doPost(request, response);
   }

   @Override
   protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
   {
      HttpSession session = request.getSession(); 
      
      OpenIDProtocolContext protoCtx = new OpenIDProtocolContext();
      
      protoCtx.setEndpoint(request.getScheme() + "://" + 
            request.getServerName() + ":" + 
            request.getServerPort() + 
            request.getContextPath() +
      "/provider/");  

      OpenIDParameterList requestp;

      if ("complete".equals(request.getParameter("_action"))) // Completing the authz and authn process by redirecting here
      {
         requestp=(OpenIDParameterList) session.getAttribute("parameterlist"); // On a redirect from the OP authn & authz sequence
      }
      else
      {
         requestp = new OpenIDParameterList(request.getParameterMap());
         Parameter openidIdentity = requestp.getParameter("openid.identity");
         if( openidIdentity != null )
         {
            session.setAttribute("openid.identity", openidIdentity.getValue()); 
         }
         else
         {
            log( "The Parameter openid.identity is null " );
         }
      }

      protoCtx.setRequestParameterList( requestp );
      
      
      String mode = requestp.hasParameter("openid.mode") ?
            requestp.getParameterValue("openid.mode") : null;

            OpenIDMessage responsem = null;
            String responseText = null;

            log("mode=" + mode + "::ParameterMap:" + requestp);

            if ("associate".equals(mode))
            {
               protoCtx.setMode( MODE.ASSOCIATE );
               try
               {
                  sts.issueToken( protoCtx );
               }
               catch (ProcessingException e)
               {
                  throw new ServletException( e );
               }
               
               responsem = protoCtx.getResponseMessage();
               
               // --- process an association request ---
               /*responsem = serverManager.processAssociationRequest(requestp);*/
               responseText = responsem.getResponseText();
            }
            else if ("checkid_setup".equals(mode)
                  || "checkid_immediate".equals(mode))
            {
               // interact with the user and obtain data needed to continue
               //List userData = userInteraction(requestp);
               String userSelectedId = null;
               String userSelectedClaimedId = null;
               Boolean authenticatedAndApproved = Boolean.FALSE;

               if ((session.getAttribute("authenticatedAndApproved") == null) ||
                     (((Boolean)session.getAttribute("authenticatedAndApproved")) == Boolean.FALSE) )
               {
                  session.setAttribute("parameterlist", requestp);
                  response.setContentType("text/html" );
                  response.sendRedirect( request.getContextPath() + "/" + this.securePageName);
                  return;
               }
               else
               {
                  userSelectedId = (String) session.getAttribute("openid.claimed_id");
                  userSelectedClaimedId = (String) session.getAttribute("openid.identity");
                  authenticatedAndApproved = (Boolean) session.getAttribute("authenticatedAndApproved");
                  // Remove the parameterlist so this provider can accept requests from elsewhere
                  session.removeAttribute("parameterlist");
                  session.setAttribute("authenticatedAndApproved", Boolean.FALSE); // Makes you authorize each and every time


                  //Fallback
                  if( authenticatedAndApproved == Boolean.TRUE && userSelectedId == null )
                  { 
                     userSelectedId = userSelectedClaimedId;
                  }
                  if( "checkid_setup".equals(mode) ) 
                     protoCtx.setMode( MODE.CHECK_ID_SETUP );
                  else
                     protoCtx.setMode( MODE.CHECK_ID_IMMEDIATE );
                  
                  protoCtx.setAuthenticationHolder( new AUTH_HOLDER(userSelectedId, 
                                                           userSelectedClaimedId, authenticatedAndApproved));
                  
                  try
                  {
                     sts.issueToken(protoCtx);
                  }
                  catch (ProcessingException e)
                  { 
                     throw new ServletException( e );
                  }
                  
                  /*// --- process an authentication request ---
                  responsem = serverManager.processAuthenticationRequest(requestp,
                        userSelectedId,
                        userSelectedClaimedId,
                        authenticatedAndApproved.booleanValue());*/
                  
                  responsem = protoCtx.getResponseMessage();

                  // caller will need to decide which of the following to use:
                  // - GET HTTP-redirect to the return_to URL
                  // - HTML FORM Redirection
                  //responseText = response.wwwFormEncoding();
                  if (responsem.isSuccessful())
                  {
                     response.sendRedirect( responsem.getDestinationURL(true));
                     return;
                  }
                  else
                  {
                     responseText="<pre>"+ responsem.getResponseText() +"</pre>";
                  }

               }
            }
            else if ("check_authentication".equals(mode))
            {
               try
               {
                  sts.validateToken( protoCtx );
               }
               catch (ProcessingException e)
               { 
                  throw new ServletException( e );
               }
               responsem = protoCtx.getResponseMessage();
               
               
               // --- processing a verification request ---
               //responsem = serverManager.verify(requestp);
               responseText = responsem.getResponseText();
            }
            else
            {
               protoCtx.setIssueError( Boolean.TRUE );
               protoCtx.setErrorText( "Unknown request" );
               try
               {
                  sts.issueToken(protoCtx);
               }
               catch (ProcessingException e)
               { 
                  throw new ServletException( e );
               }
               responsem = protoCtx.getResponseMessage();
               
               // --- error response ---
               //responsem = serverManager.getDirectError("Unknown request");
               responseText = responsem.getResponseText();
            }

            log( "response="+responseText );
            response.getWriter().write(responseText);
   }   
}