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
package org.picketlink.identity.federation.core.wstrust.writers;


import static org.picketlink.identity.federation.core.wsse.WSSecurityConstants.ID;
import static org.picketlink.identity.federation.core.wsse.WSSecurityConstants.USERNAME;
import static org.picketlink.identity.federation.core.wsse.WSSecurityConstants.USERNAME_TOKEN;
import static org.picketlink.identity.federation.core.wsse.WSSecurityConstants.WSSE_NS;
import static org.picketlink.identity.federation.core.wsse.WSSecurityConstants.WSSE_PREFIX;
import static org.picketlink.identity.federation.core.wsse.WSSecurityConstants.WSU_NS;
import static org.picketlink.identity.federation.core.wsse.WSSecurityConstants.WSU_PREFIX;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamWriter;

import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.util.StaxUtil;
import org.picketlink.identity.federation.core.util.StringUtil;
import org.picketlink.identity.federation.ws.wss.secext.AttributedString;
import org.picketlink.identity.federation.ws.wss.secext.UsernameTokenType;

/**
 * Write WS-Security Elements
 * @author Anil.Saldhana@redhat.com
 * @since Nov 8, 2010
 */
public class WSSecurityWriter
{
   private XMLStreamWriter writer;
   
   public WSSecurityWriter(XMLStreamWriter writer)
   {
      this.writer = writer;
   }
   
   public void write(UsernameTokenType usernameToken) throws ProcessingException
   {
      StaxUtil.writeStartElement( writer, WSSE_PREFIX, USERNAME_TOKEN, WSSE_NS );   
      StaxUtil.writeNameSpace( writer, WSSE_PREFIX, WSSE_NS );
      
      String id = usernameToken.getId();
      if( StringUtil.isNullOrEmpty( id ))
         throw new ProcessingException( " Id on the UsernameToken is null" );
      
      StaxUtil.setPrefix(writer, WSU_PREFIX, WSU_NS );
      QName wsuIDQName = new QName( WSU_NS, ID, WSU_PREFIX );
      StaxUtil.writeAttribute(writer, wsuIDQName, id );
      StaxUtil.writeNameSpace(writer, WSU_PREFIX, WSU_NS );
      
      AttributedString userNameAttr = usernameToken.getUsername();
      if( userNameAttr == null )
         throw new ProcessingException( " User Name is null on the UsernameToken" );
      
      StaxUtil.writeStartElement( writer, WSSE_PREFIX, USERNAME, WSSE_NS ); 
      StaxUtil.writeCharacters(writer, userNameAttr.getValue() ); 
      StaxUtil.writeEndElement( writer ); 

      StaxUtil.writeEndElement( writer ); 
      StaxUtil.flush( writer );
   }
}