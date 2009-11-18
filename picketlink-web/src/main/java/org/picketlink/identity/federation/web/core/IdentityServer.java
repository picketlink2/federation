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
package org.picketlink.identity.federation.web.core;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.HashSet;
import java.util.Set;
import java.util.Stack;
import java.util.concurrent.ConcurrentHashMap;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

import org.apache.log4j.Logger;
import org.picketlink.identity.federation.web.constants.GeneralConstants;

/**
 * Represents an Identity Server
 * @author Anil.Saldhana@redhat.com
 * @since Sep 17, 2009
 */
public class IdentityServer implements HttpSessionListener
{
   private static Logger log = Logger.getLogger(IdentityServer.class);
   private boolean trace = log.isTraceEnabled();
   
   //Configurable count for the active session count
   private static int count = AccessController.doPrivileged(new PrivilegedAction<Integer>()
   {
      public Integer run()
      {
         String val = System.getProperty("identity.server.log.count", "100"); 
         return Integer.parseInt(val);
      }
   });
   
   private static int activeSessionCount = 0;
   
   private STACK stack = new STACK(); 
   
   public class STACK
   {   
      private ConcurrentHashMap<String,Stack<String>> sessionParticipantsMap = 
         new ConcurrentHashMap<String, Stack<String>>();

      private ConcurrentHashMap<String, Set<String>> inTransitMap =
         new ConcurrentHashMap<String, Set<String>>();
      
      /**
       * Peek at the most recent participant in the session
       * @param sessionID
       * @return
       */
      public String peek(String sessionID)
      {
         Stack<String> stack = sessionParticipantsMap.get(sessionID);
         if(stack != null)
           return stack.peek();
         return "";
      }
      
      /**
       * Remove the most recent participant in the session
       * @param sessionID
       * @return
       */
      public String pop(String sessionID)
      {
         String result = null;
         Stack<String> stack = sessionParticipantsMap.get(sessionID);
         if(stack != null && stack.isEmpty() == false)
         {
            result = stack.pop(); 
         } 
         return result;
      }      

      /**
       * Register a participant in a session
       * @param sessionID
       * @param participant
       */
      public void register(String sessionID, String participant)
      {
         Stack<String> stack = sessionParticipantsMap.get(sessionID);
         if(stack == null)
         {
            stack = new Stack<String>();
            sessionParticipantsMap.put(sessionID, stack );
         }
         if(stack.contains(participant) == false)
            stack.push(participant); 
      }

      /**
       * For a given identity session, return the number of participants
       * @param sessionID
       * @return
       */
      public int getParticipants(String sessionID)
      {
         Stack<String> stack = sessionParticipantsMap.get(sessionID);
         if(stack != null)
            return stack.size();
         
         return 0; 
      }
      
      /**
       * Register a participant as in transit in a logout interaction
       * @param sessionID
       * @param participant
       * @return
       */
      public boolean registerTransitParticipant(String sessionID, String participant)
      {
         Set<String> transitSet = inTransitMap.get(sessionID);
         if(transitSet == null)
         {
            transitSet = new HashSet<String>();
            inTransitMap.put(sessionID, transitSet);  
         }
         if(transitSet != null)
            return transitSet.add(participant);
         return false;
      }
      
      /**
       * Deregister a participant as in transit in a logout interaction
       * @param sessionID
       * @param participant
       * @return
       */
      public boolean deRegisterTransitParticipant(String sessionID, String participant)
      {
         Set<String> transitSet = inTransitMap.get(sessionID);
         if(transitSet != null)
            return transitSet.remove(participant);
         return false;
      }
      
      /**
       * Return the number of participants in transit
       * @param sessionID
       * @return
       */
      public int getNumOfParticipantsInTransit(String sessionID)
      {
         Set<String> transitSet = inTransitMap.get(sessionID);
         if(transitSet != null)
            return transitSet.size();
         return 0; 
      }
      
      /**
       * The total number of sessions active
       * @return
       */
      public int totalSessions()
      {
         return sessionParticipantsMap.keySet().size();
      }
      
      private void put(String id)
      {
         sessionParticipantsMap.put(id, new Stack<String>());
         inTransitMap.put(id, new HashSet<String>());
      }
      
      private void remove(String id)
      {
         sessionParticipantsMap.remove(id);
         inTransitMap.remove(id);
      } 
   }
   
   /**
    * Return the active session count
    * @return
    */
   public int getActiveSessionCount()
   {
      return activeSessionCount;
   }
 
   /**
    * Return a reference to the internal stack 
    * @return
    */
   public STACK stack()
   {
      return stack;
   }
   

   /**
    * @see HttpSessionListener#sessionCreated(HttpSessionEvent)
    */
   public void sessionCreated(HttpSessionEvent sessionEvent)
   {  
      activeSessionCount++;
      
      if(activeSessionCount % count == 0)
         log.info("Active Session Count=" + activeSessionCount);
      
      HttpSession session = sessionEvent.getSession();

      if(trace)
         log.trace("Session Created with id=" + session.getId() +
               "::active session count=" + activeSessionCount);
      
      //Ensure that the IdentityServer instance is set on the servlet context
      ServletContext servletContext = session.getServletContext();
      
      IdentityServer idserver = (IdentityServer) servletContext.getAttribute(GeneralConstants.IDENTITY_SERVER);
      
      if(idserver == null)
      {
         idserver = this;
         servletContext.setAttribute(GeneralConstants.IDENTITY_SERVER, this);
      }
      
      if(idserver !=  this)
         throw new IllegalStateException("Identity Server mismatch");
      
      String id = sessionEvent.getSession().getId();
      stack.put(id); 
   }

   /**
    * @see HttpSessionListener#sessionDestroyed(HttpSessionEvent)
    */
   public void sessionDestroyed(HttpSessionEvent sessionEvent)
   {
      --activeSessionCount;

      String id = sessionEvent.getSession().getId();
      if(trace)
         log.trace("Session Destroyed with id=" + id + "::active session count=" 
               + activeSessionCount);
      stack.remove(id); 
   }
}