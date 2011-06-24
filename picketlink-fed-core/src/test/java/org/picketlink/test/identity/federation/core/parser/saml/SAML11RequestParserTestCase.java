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
package org.picketlink.test.identity.federation.core.parser.saml;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.InputStream;

import org.junit.Test;
import org.picketlink.identity.federation.core.parsers.saml.SAMLParser;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11SubjectType;
import org.picketlink.identity.federation.saml.v1.protocol.SAML11AttributeQueryType;
import org.picketlink.identity.federation.saml.v1.protocol.SAML11AuthenticationQueryType;
import org.picketlink.identity.federation.saml.v1.protocol.SAML11QueryAbstractType;
import org.picketlink.identity.federation.saml.v1.protocol.SAML11RequestType;

/**
 * Unit Test SAML 1.1 Request Parsing
 * @author Anil.Saldhana@redhat.com
 * @since Jun 24, 2011
 */
public class SAML11RequestParserTestCase
{
   @Test
   public void testSAML11RequestWithAuthQuery() throws Exception
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream configStream = tcl.getResourceAsStream("parser/saml1/saml1-request-authquery.xml");

      SAMLParser parser = new SAMLParser();
      SAML11RequestType request = (SAML11RequestType) parser.parse(configStream);
      assertNotNull(request);

      assertEquals(1, request.getMajorVersion());
      assertEquals(1, request.getMinorVersion());
      assertEquals("aaf23196-1773-2113-474a-fe114412ab72", request.getID());
      assertEquals(XMLTimeUtil.parse("2006-07-17T22:26:40Z"), request.getIssueInstant());

      SAML11QueryAbstractType query = request.getQuery();
      assertTrue(query instanceof SAML11AuthenticationQueryType);
      SAML11AuthenticationQueryType attQuery = (SAML11AuthenticationQueryType) query;

      SAML11SubjectType subject = attQuery.getSubject();
      SAML11SubjectType.SAML11SubjectTypeChoice choice = subject.getChoice();
      assertEquals("myusername", choice.getNameID().getValue());
   }

   @Test
   public void testSAML11RequestWithAttributeQuery() throws Exception
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream configStream = tcl.getResourceAsStream("parser/saml1/saml1-request-attributequery.xml");

      SAMLParser parser = new SAMLParser();
      SAML11RequestType request = (SAML11RequestType) parser.parse(configStream);
      assertNotNull(request);

      assertEquals(1, request.getMajorVersion());
      assertEquals(1, request.getMinorVersion());
      assertEquals("aaf23196-1773-2113-474a-fe114412ab72", request.getID());
      assertEquals(XMLTimeUtil.parse("2006-07-17T22:26:40Z"), request.getIssueInstant());

      SAML11QueryAbstractType query = request.getQuery();
      assertTrue(query instanceof SAML11AttributeQueryType);
      SAML11AttributeQueryType attQuery = (SAML11AttributeQueryType) query;

      SAML11SubjectType subject = attQuery.getSubject();
      SAML11SubjectType.SAML11SubjectTypeChoice choice = subject.getChoice();
      assertEquals("testID", choice.getNameID().getValue());
   }
}