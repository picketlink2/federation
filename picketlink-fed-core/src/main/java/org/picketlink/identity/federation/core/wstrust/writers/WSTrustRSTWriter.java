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

import static org.picketlink.identity.federation.core.wstrust.WSTrustConstants.BASE_NAMESPACE;
import static org.picketlink.identity.federation.core.wstrust.WSTrustConstants.RST_CONTEXT;
import static org.picketlink.identity.federation.core.wstrust.WSTrustConstants.PREFIX;
import static org.picketlink.identity.federation.core.wstrust.WSTrustConstants.RST;

import java.io.OutputStream;
import java.net.URI;

import javax.xml.stream.XMLStreamWriter;

import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.util.StaxUtil;
import org.picketlink.identity.federation.core.wstrust.WSTrustConstants;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityToken;
import org.picketlink.identity.federation.ws.policy.AppliesTo;
import org.picketlink.identity.federation.ws.trust.OnBehalfOfType;
import org.picketlink.identity.federation.ws.trust.UseKeyType;
import org.picketlink.identity.federation.ws.wss.secext.UsernameTokenType;
import org.w3c.dom.Element;

/**
 * Given a {@code RequestSecurityToken}, write into an {@code OutputStream}
 * @author Anil.Saldhana@redhat.com
 * @since Oct 19, 2010
 */
public class WSTrustRSTWriter extends AbstractWSWriter
{
   /**
    * Write the {@code RequestSecurityToken} into the {@code OutputStream}
    * @param requestToken
    * @param out
    * @throws ProcessingException
    */
   public void write( RequestSecurityToken requestToken, OutputStream out ) throws ProcessingException
   {
      verifyWriter(out);
      StaxUtil.writeStartElement( writer, PREFIX, RST, BASE_NAMESPACE);   
      StaxUtil.writeNameSpace( writer, PREFIX, BASE_NAMESPACE );
      String context = requestToken.getContext();
      StaxUtil.writeAttribute( writer,  RST_CONTEXT, context );
      
      URI requestType = requestToken.getRequestType();
      if( requestType != null )
      {
         writeRequestType( writer, requestType );
      }
      
      URI tokenType = requestToken.getTokenType();
      if( tokenType != null )
      {
         writeTokenType( writer, tokenType );
      }
      //Deal with AppliesTo
      AppliesTo appliesTo = requestToken.getAppliesTo();
      if( appliesTo != null )
      {
         WSPolicyWriter wsPolicyWriter = new WSPolicyWriter();
         wsPolicyWriter.write( appliesTo, out ); 
      }
      
      URI keyType = requestToken.getKeyType();
      if( keyType != null )
      {
         StaxUtil.writeStartElement( writer, PREFIX, WSTrustConstants.KEY_TYPE, BASE_NAMESPACE);   
         StaxUtil.writeCharacters(writer,  keyType.toString() ); 
         StaxUtil.writeEndElement( writer ); 
      }
      
      UseKeyType useKeyType = requestToken.getUseKey();
      if( useKeyType != null )
      {
         Object useKeyTypeValue = useKeyType.getAny();
         if( useKeyTypeValue instanceof Element )
         {
            Element domElement = (Element) useKeyTypeValue;
            StaxUtil.writeDOMElement( writer, domElement ); 
         }
         else
            throw new RuntimeException( " Unknown use key type:" + useKeyTypeValue.getClass().getName() );
      }
      
      OnBehalfOfType onBehalfOf = requestToken.getOnBehalfOf();
      if( onBehalfOf != null )
      { 
         StaxUtil.writeStartElement( writer, PREFIX, WSTrustConstants.On_BEHALF_OF, BASE_NAMESPACE); 
         StaxUtil.writeCharacters(writer, "" ); 
         
         UsernameTokenType usernameToken = (UsernameTokenType) onBehalfOf.getAny(); 
         WSSecurityWriter wsseWriter = new WSSecurityWriter();
         wsseWriter.write( usernameToken, out );
         StaxUtil.writeEndElement( writer ); 
      }
      
      StaxUtil.writeEndElement( writer ); 
      StaxUtil.flush( writer );
   }
    
   private void writeRequestType( XMLStreamWriter writer , URI uri ) throws ProcessingException
   {
      StaxUtil.writeStartElement( writer, PREFIX, WSTrustConstants.REQUEST_TYPE, BASE_NAMESPACE );
      StaxUtil.writeCharacters(writer, uri.toASCIIString() );
      StaxUtil.writeEndElement(writer);
   }
   
   private void writeTokenType( XMLStreamWriter writer , URI uri ) throws ProcessingException
   {
      StaxUtil.writeStartElement( writer, PREFIX, WSTrustConstants.TOKEN_TYPE, BASE_NAMESPACE );
      StaxUtil.writeCharacters(writer, uri.toASCIIString() );
      StaxUtil.writeEndElement(writer);
   }
}