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
package org.picketlink.test.identity.federation.core.parser.wst;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import javax.xml.bind.JAXBElement;

import org.junit.Test;
import org.picketlink.identity.federation.core.parsers.wst.WSTRequestSecurityTokenParser;
import org.picketlink.identity.federation.core.parsers.wst.WSTrustParser;
import org.picketlink.identity.federation.core.saml.v2.util.DocumentUtil;
import org.picketlink.identity.federation.core.wstrust.WSTrustConstants;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityToken;
import org.picketlink.identity.federation.core.wstrust.writers.WSTrustRSTWriter;
import org.picketlink.identity.federation.ws.addressing.EndpointReferenceType;
import org.picketlink.identity.federation.ws.policy.AppliesTo;
import org.picketlink.identity.federation.ws.trust.UseKeyType;
import org.w3c.dom.Element;

/**
 * Validate parsing of RST with Use Key set to a RSA Public Key
 * @author Anil.Saldhana@redhat.com
 * @since Oct 18, 2010
 */
public class WSTrustIssuePublicKeyTestCase
{

   @SuppressWarnings("unchecked")
   @Test
   public void testPublicKey() throws Exception
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream configStream = tcl.getResourceAsStream( "parser/wst/wst-issue-public-key.xml" );
      
      WSTrustParser parser = new WSTrustParser();
      RequestSecurityToken requestToken = ( RequestSecurityToken ) parser.parse( configStream );   
       
      assertEquals( "testcontext", requestToken.getContext() );
      assertEquals( WSTrustConstants.ISSUE_REQUEST , requestToken.getRequestType().toASCIIString() ); 
      
      AppliesTo appliesTo = requestToken.getAppliesTo();
      JAXBElement<EndpointReferenceType> jaxb = (JAXBElement<EndpointReferenceType>) appliesTo.getAny().get(0);
      EndpointReferenceType endpoint = jaxb.getValue();
      assertEquals( "http://services.testcorp.org/provider2", endpoint.getAddress().getValue() );
      
      
      assertEquals( "http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey", requestToken.getKeyType().toASCIIString() );
      
      UseKeyType useKeyType = requestToken.getUseKey();
      Element certEl = (Element) useKeyType.getAny(); 
      
      assertEquals( "ds:" + WSTRequestSecurityTokenParser.KEYVALUE, certEl.getTagName() );
      

      //Now for the writing part
      WSTrustRSTWriter rstWriter = new WSTrustRSTWriter();
      ByteArrayOutputStream baos = new ByteArrayOutputStream();

      rstWriter.write(requestToken, baos ); 

      System.out.println( new String( baos.toByteArray() ));
      DocumentUtil.getDocument( new ByteArrayInputStream( baos.toByteArray() )); 
   }
}