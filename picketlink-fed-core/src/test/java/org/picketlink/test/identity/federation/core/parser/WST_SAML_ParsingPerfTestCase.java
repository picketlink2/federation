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
package org.picketlink.test.identity.federation.core.parser;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import javax.xml.transform.Source;

import org.junit.Ignore;
import org.junit.Test;
import org.picketlink.identity.federation.core.parsers.wst.WSTrustParser;
import org.picketlink.identity.federation.core.saml.v2.util.DocumentUtil;
import org.picketlink.identity.federation.core.wstrust.WSTrustJAXBFactory;
import org.w3c.dom.Document;

/**
 * Some simple perf tests
 * @author Anil.Saldhana@redhat.com
 * @since Oct 14, 2010
 */
public class WST_SAML_ParsingPerfTestCase
{
   private int runs = 5000;

   String fileName = "parser/perf/wst-batch-validate-one.xml";
   
   /**
    * This test just tests some saml/wst payload performance
    * using JAXB and Stax.
    * 
    * <b>NOTE:</b> For the test to work, just comment out @Ignore
    * @throws Exception
    */
   @Test
   @Ignore
   public void testParsingPerformance() throws Exception
   {
      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream configStream = tcl.getResourceAsStream( fileName );
      
      Document doc = DocumentUtil.getDocument( configStream );
      Source source =  DocumentUtil.getXMLSource(doc);
      
     
      //JAXB way
      long start = System.currentTimeMillis(); 
      for( int i = 0 ; i < runs; i++ )
      {
         useJAXB( source ); 
      }
      long elapsedTimeMillis = System.currentTimeMillis() - start; 
      System.out.println("JAXB, time spent for " + runs  
            + " iterations = " + elapsedTimeMillis + " ms or " + elapsedTimeMillis/1000F + " secs");

      configStream = tcl.getResourceAsStream( fileName );
      byte[] xmlData = new byte[ configStream.available() ];
      configStream.read( xmlData );

      //Stax Way
      start = System.currentTimeMillis(); 
      for( int i = 0 ; i < runs; i++ )
      {
         useStax( new ByteArrayInputStream( xmlData ) );
      }
      elapsedTimeMillis = System.currentTimeMillis() - start; 
      System.out.println("STAX, time spent for " + runs  
            + " iterations = " + elapsedTimeMillis + " ms or " + elapsedTimeMillis/1000F + " secs");
   }
   
   private void useJAXB( Source source ) throws Exception
   {
      WSTrustJAXBFactory.getInstance().parseRequestSecurityToken(source); 
   }
   
   private void useStax( InputStream configStream ) throws Exception
   {   
      WSTrustParser parser = new WSTrustParser();
      parser.parse( configStream );  
   }
}