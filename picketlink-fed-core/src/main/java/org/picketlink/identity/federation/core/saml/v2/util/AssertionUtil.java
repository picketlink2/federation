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
package org.picketlink.identity.federation.core.saml.v2.util;

import javax.xml.datatype.XMLGregorianCalendar;

import org.apache.log4j.Logger;
import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLConstants;
import org.picketlink.identity.federation.core.saml.v2.exceptions.IssueInstantMissingException;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AttributeType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.ConditionsType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.NameIDType;

/**
 * Utility to deal with assertions
 * @author Anil.Saldhana@redhat.com
 * @since Jun 3, 2009
 */
public class AssertionUtil
{ 
   private static Logger log = Logger.getLogger(AssertionUtil.class);
   private static boolean trace = log.isTraceEnabled();
   
   /**
    * Create an assertion
    * @param id
    * @param issuer
    * @return
    */
   public static AssertionType createAssertion(String id, NameIDType issuer)
   {
      XMLGregorianCalendar issueInstant = null;
      try
      {
         issueInstant = XMLTimeUtil.getIssueInstant();
      }
      catch (ConfigurationException e)
      {
         throw new RuntimeException( e );
      }
      AssertionType assertion =  new AssertionType( id, issueInstant, JBossSAMLConstants.VERSION_2_0.get() ); 
      assertion.setIssuer( issuer );
      return assertion; 
   }
   
   /**
    * Create an attribute type
    * @param name Name of the attribute
    * @param nameFormat name format uri
    * @param attributeValues an object array of attribute values
    * @return
    */
   public static AttributeType createAttribute(String name, String nameFormat,
         Object... attributeValues)
   { 
      AttributeType att = new AttributeType( name ); 
      att.setNameFormat(nameFormat);
      if(attributeValues != null && attributeValues.length > 0)
      {
         for(Object attributeValue:attributeValues)
         {
            att.addAttributeValue(attributeValue);
         } 
      }
 
      return att;
   }
   
   /**
    * Add validity conditions to the SAML2 Assertion
    * @param assertion
    * @param durationInMilis   
    * @throws ConfigurationException 
    * @throws IssueInstantMissingException 
    */
   public static void createTimedConditions(AssertionType assertion, long durationInMilis) 
   throws ConfigurationException, IssueInstantMissingException  
   {
      XMLGregorianCalendar issueInstant = assertion.getIssueInstant();
      if(issueInstant == null)
         throw new IssueInstantMissingException("assertion does not have issue instant");
      XMLGregorianCalendar assertionValidityLength = XMLTimeUtil.add(issueInstant, durationInMilis);
      ConditionsType conditionsType = new ConditionsType();
      conditionsType.setNotBefore(issueInstant);
      conditionsType.setNotOnOrAfter(assertionValidityLength);
      
      assertion.setConditions(conditionsType); 
   }
   
   /**
    * Check whether the assertion has expired
    * @param assertion
    * @return
    * @throws ConfigurationException
    */
   public static boolean hasExpired(AssertionType assertion) throws ConfigurationException
   {
      //Check for validity of assertion
      ConditionsType conditionsType = assertion.getConditions();
      if(conditionsType != null)
      {
         XMLGregorianCalendar now = XMLTimeUtil.getIssueInstant();
         XMLGregorianCalendar notBefore = conditionsType.getNotBefore();
         XMLGregorianCalendar notOnOrAfter = conditionsType.getNotOnOrAfter();
         if(trace) log.trace("Now="+now.toXMLFormat() + " ::notBefore="+notBefore.toXMLFormat() 
               + "::notOnOrAfter="+notOnOrAfter);
         return !XMLTimeUtil.isValid(now, notBefore, notOnOrAfter); 
      }
      //TODO: if conditions do not exist, assume the assertion to be everlasting?
      return false; 
   } 
}