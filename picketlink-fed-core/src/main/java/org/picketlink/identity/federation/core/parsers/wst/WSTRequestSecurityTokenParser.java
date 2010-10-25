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
package org.picketlink.identity.federation.core.parsers.wst;

import java.net.URI;
import java.net.URISyntaxException;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import javax.xml.transform.Transformer;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.stax.StAXSource;

import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.parsers.ParserController;
import org.picketlink.identity.federation.core.parsers.ParserNamespaceSupport;
import org.picketlink.identity.federation.core.parsers.util.StaxParserUtil;
import org.picketlink.identity.federation.core.saml.v2.util.DocumentUtil;
import org.picketlink.identity.federation.core.util.TransformerUtil;
import org.picketlink.identity.federation.core.wstrust.WSTrustConstants;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityToken;
import org.picketlink.identity.federation.ws.policy.AppliesTo;
import org.picketlink.identity.federation.ws.trust.BinarySecretType;
import org.picketlink.identity.federation.ws.trust.CancelTargetType;
import org.picketlink.identity.federation.ws.trust.EntropyType;
import org.picketlink.identity.federation.ws.trust.OnBehalfOfType;
import org.picketlink.identity.federation.ws.trust.RenewTargetType;
import org.picketlink.identity.federation.ws.trust.UseKeyType;
import org.picketlink.identity.federation.ws.trust.ValidateTargetType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Parse the WS-Trust RequestSecurityToken
 * @author Anil.Saldhana@redhat.com
 * @since Oct 11, 2010
 */
public class WSTRequestSecurityTokenParser implements ParserNamespaceSupport
{  
   public static final String X509CERTIFICATE = "X509Certificate";
   public static final String KEYVALUE = "KeyValue";

   public static final String JDK_TRANSFORMER_PROPERTY = "picketlink.jdk.transformer";

   /**
    * @see {@link ParserNamespaceSupport#parse(XMLEventReader)}
    */
   public Object parse(XMLEventReader xmlEventReader) throws ParsingException
   { 
      StartElement startElement =  StaxParserUtil.getNextStartElement( xmlEventReader ); 

      RequestSecurityToken requestToken = new RequestSecurityToken();

      QName contextQName = new QName( "", WSTrustConstants.RST_CONTEXT );
      Attribute contextAttribute = startElement.getAttributeByName( contextQName );
      String contextValue = StaxParserUtil.getAttributeValue( contextAttribute );
      requestToken.setContext( contextValue ); 

      while( xmlEventReader.hasNext() )
      {
         XMLEvent xmlEvent = StaxParserUtil.peek( xmlEventReader );
         if( xmlEvent == null )
            break;
         if( xmlEvent instanceof EndElement )
         {
            xmlEvent = StaxParserUtil.getNextEvent( xmlEventReader );
            EndElement endElement = (EndElement) xmlEvent;
            String endElementTag = StaxParserUtil.getEndElementName( endElement );
            if( endElementTag.equals( WSTrustConstants.RST ) )
               break;
         }

         try
         {
            StartElement subEvent = StaxParserUtil.peekNextStartElement( xmlEventReader );
            if( subEvent == null )
               break;

            String tag = StaxParserUtil.getStartElementName( subEvent );
            if( tag.equals( WSTrustConstants.REQUEST_TYPE ))
            { 
               subEvent = StaxParserUtil.getNextStartElement(xmlEventReader);

               if( !StaxParserUtil.hasTextAhead( xmlEventReader ))
                  throw new ParsingException( "request type is expected ahead" );

               String value = StaxParserUtil.getElementText(xmlEventReader);
               requestToken.setRequestType( new URI( value ));
            }
            else if( tag.equals( WSTrustConstants.TOKEN_TYPE  ))
            {
               subEvent = StaxParserUtil.getNextStartElement(xmlEventReader);

               if( !StaxParserUtil.hasTextAhead( xmlEventReader ))
                  throw new ParsingException( "token type is expected ahead" );

               String value = StaxParserUtil.getElementText(xmlEventReader);
               requestToken.setTokenType( new URI( value ));
            }
            else if( tag.equals( WSTrustConstants.CANCEL_TARGET ))
            {
               subEvent = StaxParserUtil.getNextStartElement(xmlEventReader);
               StaxParserUtil.validate(subEvent, WSTrustConstants.CANCEL_TARGET );
               WSTCancelTargetParser wstCancelTargetParser = new WSTCancelTargetParser();
               CancelTargetType cancelTarget = (CancelTargetType) wstCancelTargetParser.parse( xmlEventReader );
               requestToken.setCancelTarget( cancelTarget ); 
               EndElement cancelTargetEndElement = StaxParserUtil.getNextEndElement(xmlEventReader);
               StaxParserUtil.validate( cancelTargetEndElement, WSTrustConstants.CANCEL_TARGET ) ; 
            }
            else if( tag.equals( WSTrustConstants.VALIDATE_TARGET ))
            {
               subEvent = StaxParserUtil.getNextStartElement(xmlEventReader);

               WSTValidateTargetParser wstValidateTargetParser = new WSTValidateTargetParser();
               ValidateTargetType validateTarget = (ValidateTargetType) wstValidateTargetParser.parse( xmlEventReader );
               requestToken.setValidateTarget( validateTarget ); 
               EndElement validateTargetEndElement = StaxParserUtil.getNextEndElement(xmlEventReader);
               StaxParserUtil.validate( validateTargetEndElement, WSTrustConstants.VALIDATE_TARGET ) ;
            } 
            else if( tag.equals( WSTrustConstants.RENEW_TARGET ))
            {
               subEvent = StaxParserUtil.getNextStartElement(xmlEventReader);

               WSTRenewTargetParser wstValidateTargetParser = new WSTRenewTargetParser();
               RenewTargetType validateTarget = (RenewTargetType) wstValidateTargetParser.parse( xmlEventReader );
               requestToken.setRenewTarget( validateTarget ); 
               EndElement validateTargetEndElement = StaxParserUtil.getNextEndElement(xmlEventReader);
               StaxParserUtil.validate( validateTargetEndElement, WSTrustConstants.RENEW_TARGET ) ;
            } 
            else if( tag.equals( WSTrustConstants.On_BEHALF_OF ))
            {
               subEvent = StaxParserUtil.getNextStartElement(xmlEventReader);

               WSTrustOnBehalfOfParser wstOnBehalfOfParser = new WSTrustOnBehalfOfParser(); 
               OnBehalfOfType onBehalfOf = (OnBehalfOfType) wstOnBehalfOfParser.parse(xmlEventReader); 
               requestToken.setOnBehalfOf(onBehalfOf);
               EndElement onBehalfOfEndElement = StaxParserUtil.getNextEndElement(xmlEventReader);
               StaxParserUtil.validate( onBehalfOfEndElement, WSTrustConstants.On_BEHALF_OF ) ;
            }  
            else if( tag.equals( WSTrustConstants.KEY_TYPE ))
            {
               subEvent = StaxParserUtil.getNextStartElement(xmlEventReader);
               if( !StaxParserUtil.hasTextAhead( xmlEventReader ))
                  throw new ParsingException( "key type is expected ahead" );

               String keyType = StaxParserUtil.getElementText(xmlEventReader);
               try
               {
                  URI keyTypeURI = new URI( keyType );
                  requestToken.setKeyType( keyTypeURI );
               }
               catch( URISyntaxException e )
               {
                  throw new ParsingException( e );
               }  
            } 
            else if( tag.equals( WSTrustConstants.KEY_SIZE ))
            {
               subEvent = StaxParserUtil.getNextStartElement(xmlEventReader);

               if( !StaxParserUtil.hasTextAhead( xmlEventReader ))
                  throw new ParsingException( "key size is expected ahead" );

               String keySize = StaxParserUtil.getElementText(xmlEventReader);
               try
               { 
                  requestToken.setKeySize(Long.parseLong( keySize ));
               }
               catch( NumberFormatException e )
               {
                  throw new ParsingException( e );
               }  
            } 
            else if( tag.equals( WSTrustConstants.ENTROPY ))
            {
               subEvent = StaxParserUtil.getNextStartElement(xmlEventReader); 
               EntropyType entropy = new EntropyType();
               subEvent = StaxParserUtil.getNextStartElement(xmlEventReader);
               if( StaxParserUtil.matches(subEvent, WSTrustConstants.BINARY_SECRET ))
               {
                  BinarySecretType binarySecret = new BinarySecretType();
                  Attribute typeAttribute = subEvent.getAttributeByName( new QName( "", "Type" ));
                  binarySecret.setType( StaxParserUtil.getAttributeValue( typeAttribute ));

                  if( !StaxParserUtil.hasTextAhead( xmlEventReader ))
                     throw new ParsingException( "binary secret value is expected ahead" );

                  binarySecret.setValue( StaxParserUtil.getElementText(xmlEventReader).getBytes() ); 
                  entropy.getAny().add( binarySecret );
               }
               requestToken.setEntropy(entropy);
            }
            else if( tag.equals( WSTrustConstants.USE_KEY ))
            {
               subEvent = StaxParserUtil.getNextStartElement(xmlEventReader); 
               UseKeyType useKeyType = new UseKeyType();  
               StaxParserUtil.validate( subEvent, WSTrustConstants.USE_KEY ) ;

               //We peek at the next start element as the stax source has to be in the START_ELEMENT mode
               subEvent = StaxParserUtil.peekNextStartElement(xmlEventReader); 
               if( StaxParserUtil.matches(subEvent, X509CERTIFICATE ))
               {
                  Element domElement = this.getDOMElement(xmlEventReader);
                  //Element domElement = getX509CertificateAsDomElement( subEvent, xmlEventReader );

                  useKeyType.setAny( domElement );
                  requestToken.setUseKey( useKeyType );   
               } 
               else if( StaxParserUtil.matches(subEvent, KEYVALUE ))
               {
                  //Element domElement = getKeyValueAsDomElement( subEvent, xmlEventReader );
                  Element domElement = this.getDOMElement(xmlEventReader);//
                  useKeyType.setAny( domElement );
                  requestToken.setUseKey( useKeyType );   
               }
               else throw new RuntimeException( "unsupported " + StaxParserUtil.getStartElementName( subEvent )); 
            }  
            else
            {
               QName qname = subEvent.getName();
               ParserNamespaceSupport parser = ParserController.get( qname );
               if( parser == null )
                  throw new RuntimeException( "Cannot parse " + qname ); 

               Object parsedObject = parser.parse( xmlEventReader );
               if( parsedObject instanceof AppliesTo )
               {
                  requestToken.setAppliesTo( (AppliesTo) parsedObject );
               }
            }
         } 
         catch (URISyntaxException e)
         {
            throw new ParsingException( e );
         }   
      }

      return requestToken;
   }

   /**
    * @see {@link ParserNamespaceSupport#supports(QName)}
    */
   public boolean supports(QName qname)
   { 
      String nsURI = qname.getNamespaceURI();
      String localPart = qname.getLocalPart();

      return WSTrustConstants.BASE_NAMESPACE.equals( nsURI )
      && WSTrustConstants.RST.equals( localPart );
   } 

   /**
    * Given that the {@code XMLEventReader} is in {@code XMLStreamConstants.START_ELEMENT}
    * mode, we parse into a DOM Element
    * @param xmlEventReader
    * @return
    * @throws ParsingException
    */
   private Element getDOMElement( XMLEventReader xmlEventReader ) throws ParsingException
   {
      Transformer transformer = null;

      boolean useJDKTransformer = Boolean.parseBoolean( SecurityActions.getSystemProperty(JDK_TRANSFORMER_PROPERTY, "false" ));

      try
      { 
         if( useJDKTransformer )
         {
            transformer = TransformerUtil.getTransformer();
         }
         else
         {
            transformer = TransformerUtil.getStaxSourceToDomResultTransformer();
         } 

         Document resultDocument = DocumentUtil.createDocument();
         DOMResult domResult = new DOMResult( resultDocument );
 
         StAXSource source = new StAXSource( xmlEventReader );

         TransformerUtil.transform( transformer, source, domResult );

         Document doc = ( Document ) domResult.getNode();
         return doc.getDocumentElement();
      }
      catch ( ConfigurationException e )
      {
         throw new ParsingException( e );
      }
      catch ( XMLStreamException e )
      {
         throw new ParsingException( e );
      }
   } 
}