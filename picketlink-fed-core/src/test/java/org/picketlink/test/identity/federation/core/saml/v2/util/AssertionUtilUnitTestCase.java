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
package org.picketlink.test.identity.federation.core.saml.v2.util;

import javax.xml.datatype.XMLGregorianCalendar;

import junit.framework.TestCase;

import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLConstants;
import org.picketlink.identity.federation.core.saml.v2.util.AssertionUtil;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.ConditionsType;
import org.picketlink.identity.federation.newmodel.saml.v2.assertion.NameIDType;

/**
 * Unit test the AssertionUtil
 * @author Anil.Saldhana@redhat.com
 * @since Jun 3, 2009
 */
public class AssertionUtilUnitTestCase extends TestCase
{ 
   
   public void testValidAssertion() throws Exception
   {
      NameIDType nameIdType =  new NameIDType();
      nameIdType.setValue("somename");
      
      AssertionType assertion = new AssertionType( "SomeID", XMLTimeUtil.getIssueInstant(), JBossSAMLConstants.VERSION_2_0.get() );
      assertion.setIssuer(nameIdType);
      
      //Assertions with no conditions are everlasting
      assertTrue(AssertionUtil.hasExpired(assertion) == false);
      
      XMLGregorianCalendar now = XMLTimeUtil.getIssueInstant();
      
      XMLGregorianCalendar sometimeLater = XMLTimeUtil.add(now, 5555);
      
      ConditionsType conditions = new ConditionsType();
      conditions.setNotBefore(now);
      conditions.setNotOnOrAfter(sometimeLater);
      assertion.setConditions(conditions); 
      assertTrue(AssertionUtil.hasExpired(assertion) == false);
   }
   
   public void testExpiredAssertion() throws Exception
   {
      
      NameIDType nameIdType = new NameIDType();
      nameIdType.setValue("somename");
      
      AssertionType assertion = new AssertionType( "SomeID", XMLTimeUtil.getIssueInstant(), JBossSAMLConstants.VERSION_2_0.get());
      assertion.setIssuer(nameIdType); 
      
      XMLGregorianCalendar now = XMLTimeUtil.getIssueInstant();
      
      XMLGregorianCalendar sometimeAgo = XMLTimeUtil.subtract(now, 55555);
      
      ConditionsType conditions = new ConditionsType();
      conditions.setNotBefore(XMLTimeUtil.subtract(now,55575));
      conditions.setNotOnOrAfter(sometimeAgo);
      assertion.setConditions(conditions); 
      assertTrue(AssertionUtil.hasExpired(assertion));
   }    
}