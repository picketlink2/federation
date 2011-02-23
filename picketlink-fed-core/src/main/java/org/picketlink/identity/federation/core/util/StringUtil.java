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
package org.picketlink.identity.federation.core.util;

import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;


/**
 * Utility dealing with Strings
 * @author Anil.Saldhana@redhat.com
 * @since Oct 21, 2009
 */
public class StringUtil
{
   /**
    * Check whether the passed string is null or empty
    * @param str
    * @return
    */
   public static boolean isNotNull(String str)
   {
      return str != null && !"".equals(str);
   } 
   
   /**
    * Check whether the string is null or empty
    * @param str
    * @return
    */
   public static boolean isNullOrEmpty(String str)
   {
      return str == null || str.isEmpty();
   }
    
   /**
    * Get the system property value if the string is of the format ${sysproperty}
    * @param str
    * @return
    */
   public static String getSystemPropertyAsString( String str )
   {
      if( str.startsWith( "${") && str.endsWith( "}" ))
      {
         int len = str.length();
         str = str.substring( 2, len -1 );
         String sysPropertyValue = SecurityActions.getSystemProperty(str, "" );
         if( sysPropertyValue.isEmpty() )
            throw new IllegalArgumentException( "System Property " + str + " is not set" );
         str = sysPropertyValue;
      }
      return str;
   }
   
   /**
    * Given a comma separated string, get the tokens as a {@link List}
    * @param str
    * @return
    */
   public static List<String> tokenize( String str )
   {
      List<String> list = new ArrayList<String>();
      StringTokenizer tokenizer = new StringTokenizer(str, ",");
      while( tokenizer.hasMoreTokens() )
      {
         list.add( tokenizer.nextToken() );
      }
      return list;
   }
}