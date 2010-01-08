/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2009, Red Hat Middleware LLC, and individual contributors
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
package org.picketlink.identity.federation.core.wstrust;

import javax.xml.bind.Binder;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMSource;

import org.apache.log4j.Logger;
import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.saml.v2.common.SAMLDocumentHolder;
import org.picketlink.identity.federation.core.saml.v2.util.DocumentUtil;
import org.picketlink.identity.federation.core.util.JAXBUtil;
import org.picketlink.identity.federation.core.wstrust.wrappers.BaseRequestSecurityToken;
import org.picketlink.identity.federation.core.wstrust.wrappers.BaseRequestSecurityTokenResponse;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityToken;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityTokenResponse;
import org.picketlink.identity.federation.core.wstrust.wrappers.RequestSecurityTokenResponseCollection;
import org.picketlink.identity.federation.ws.trust.ObjectFactory;
import org.picketlink.identity.federation.ws.trust.RequestSecurityTokenResponseCollectionType;
import org.picketlink.identity.federation.ws.trust.RequestSecurityTokenType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * <p>
 * This factory implements utility methods for converting between JAXB model objects and XML source.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public class WSTrustJAXBFactory
{
   private static Logger log = Logger.getLogger(WSTrustJAXBFactory.class);
   private boolean trace = log.isTraceEnabled();
   
   private static final WSTrustJAXBFactory instance = new WSTrustJAXBFactory();

   private Marshaller marshaller;

   private Unmarshaller unmarshaller;
   
   private Binder<Node> binder;

   private final ObjectFactory objectFactory;
   
   private ThreadLocal<SAMLDocumentHolder> holders = new ThreadLocal<SAMLDocumentHolder>();

   /**
    * <p>
    * Creates the {@code WSTrustJAXBFactory} singleton instance.
    * </p>
    */
   private WSTrustJAXBFactory()
   {
      try
      {
         this.marshaller = JAXBUtil.getMarshaller(this.getPackages());
         this.unmarshaller = JAXBUtil.getUnmarshaller(this.getPackages());
         this.binder = JAXBUtil.getJAXBContext(this.getPackages()).createBinder();
         this.objectFactory = new ObjectFactory();
      }
      catch (JAXBException e)
      {
         throw new RuntimeException(e.getMessage(), e);
      }
   }

   /**
    * <p>
    * Gets a reference to the singleton instance.
    * </p>
    * 
    * @return a reference to the {@code WSTrustJAXBFactory} instance.
    */
   public static WSTrustJAXBFactory getInstance()
   {
      return instance;
   }

   private String getPackages()
   {
      StringBuilder packages = new StringBuilder();
      packages.append("org.picketlink.identity.federation.ws.addressing");
      packages.append(":org.picketlink.identity.federation.ws.policy");
      packages.append(":org.picketlink.identity.federation.ws.trust");
      packages.append(":org.picketlink.identity.federation.ws.wss.secext");
      packages.append(":org.picketlink.identity.federation.ws.wss.utility");
      return packages.toString();
   }

   /**
    * <p>
    * Creates a {@code BaseRequestSecurityToken} from the specified XML source.
    * </p>
    * 
    * @param request
    *           the XML source containing the security token request message.
    * @return the constructed {@code BaseRequestSecurityToken} instance. It will be an instance of {@code
    *         RequestSecurityToken} the message contains a single token request, and an instance of {@code
    *         RequestSecurityTokenCollection} if multiples requests are being made in the same message.
    * @throws ParsingException 
    */
   @SuppressWarnings("unchecked")
   public BaseRequestSecurityToken parseRequestSecurityToken(Source request) throws ParsingException
   {
      // if the request contains a validate, cancel, or renew target, we must preserve it from JAXB unmarshalling.
	  Node documentNode = ((DOMSource) request).getNode();
      Document document = documentNode instanceof Document ? (Document) documentNode : documentNode.getOwnerDocument();
      
      JAXBElement<RequestSecurityTokenType> jaxbRST;
      try
      {
         Node rst = this.findNodeByNameNS(document, "RequestSecurityToken", WSTrustConstants.BASE_NAMESPACE);
         if(rst == null)
            throw new RuntimeException("Request Security Token node not found");
         
         jaxbRST = (JAXBElement<RequestSecurityTokenType>) binder.unmarshal(rst);

         RequestSecurityTokenType rstt = jaxbRST.getValue();
         
         SAML2SecurityToken samlSecurityToken = new SAML2SecurityToken(rstt);
         holders.set(new SAMLDocumentHolder(samlSecurityToken, document));
         return new RequestSecurityToken(rstt);
      }
      catch (JAXBException e)
      {
         throw new ParsingException(e);
      }
   }

   /**
    * <p>
    * Creates a {@code BaseRequestSecurityTokenResponse} from the specified XML source.
    * </p>
    * 
    * @param response
    *           the XML source containing the security token response message.
    * @return the constructed {@code BaseRequestSecurityTokenResponse} instance. According to the WS-Trust
    *         specification, the returned object will be an instance of {@code RequestSecurityTokenResponseCollection}.
    */
   @SuppressWarnings("unchecked")
   public BaseRequestSecurityTokenResponse parseRequestSecurityTokenResponse(Source response)
   {
      // if the response contains an issued token, we must preserve it from the JAXB unmarshalling.
      Element tokenElement = null;
	  Node documentNode = ((DOMSource) response).getNode();
      Document document = documentNode instanceof Document ? (Document) documentNode : documentNode.getOwnerDocument();
      Node requestedTokenNode = this.findNodeByNameNS(document, "RequestedSecurityToken",
            WSTrustConstants.BASE_NAMESPACE);
      if (requestedTokenNode != null)
         tokenElement = (Element) requestedTokenNode.getFirstChild();

      try
      {
         Object object = this.unmarshaller.unmarshal(response);
         if (object instanceof JAXBElement)
         {
            JAXBElement<?> element = (JAXBElement<?>) unmarshaller.unmarshal(response);
            if (element.getDeclaredType().equals(RequestSecurityTokenResponseCollectionType.class))
            {
               RequestSecurityTokenResponseCollection collection = new RequestSecurityTokenResponseCollection(
                     (RequestSecurityTokenResponseCollectionType) element.getValue());
               // insert the security token in the parsed response.
               if (tokenElement != null)
               {
                  RequestSecurityTokenResponse parsedResponse = collection.getRequestSecurityTokenResponses().get(0);
                  parsedResponse.getRequestedSecurityToken().setAny(tokenElement);
               }
               return collection;
            }
            else
               throw new RuntimeException("Invalid response type: " + element.getDeclaredType());
         }
         else
            throw new RuntimeException("Invalid response type: " + object.getClass().getName());
      }
      catch (Exception e)
      {
         throw new RuntimeException("Failed to unmarshall security token response", e);
      }
   }

   /**
    * <p>
    * Creates a {@code javax.xml.transform.Source} from the specified request object.
    * </p>
    * 
    * @param request
    *           a {@code RequestSecurityToken} representing the object model of the security token request.
    * @return the constructed {@code Source} instance.
    */
   public Source marshallRequestSecurityToken(RequestSecurityToken request)
   {
      Element targetElement = null;
      // if the request has a validate, cancel, or renew target, we must preserve it from JAXB marshaling.
      String requestType = request.getRequestType().toString();
      if (requestType.equalsIgnoreCase(WSTrustConstants.VALIDATE_REQUEST) && request.getValidateTarget() != null)
      {
         targetElement = (Element) request.getValidateTarget().getAny();
         request.getValidateTarget().setAny(null);
      }
      else if (requestType.equalsIgnoreCase(WSTrustConstants.RENEW_REQUEST) && request.getRenewTarget() != null)
      {
         targetElement = (Element) request.getRenewTarget().getAny();
         request.getRenewTarget().setAny(null);
      }
      else if (requestType.equalsIgnoreCase(WSTrustConstants.CANCEL_REQUEST) && request.getCancelTarget() != null)
      {
         targetElement = (Element) request.getCancelTarget().getAny();
         request.getCancelTarget().setAny(null);
      }

      Document result = null;
      try
      {
         result = DocumentUtil.createDocument();
         this.marshaller.marshal(this.objectFactory.createRequestSecurityToken(request.getDelegate()), result);

         // insert the original target in the appropriate element. 
         if (targetElement != null)
         {
            Node node = null;
            if (requestType.equalsIgnoreCase(WSTrustConstants.VALIDATE_REQUEST))
               node = this.findNodeByNameNS(result, "ValidateTarget", WSTrustConstants.BASE_NAMESPACE);
            else if (requestType.equalsIgnoreCase(WSTrustConstants.RENEW_REQUEST))
               node = this.findNodeByNameNS(result, "RenewTarget", WSTrustConstants.BASE_NAMESPACE);
            else if (requestType.equalsIgnoreCase(WSTrustConstants.CANCEL_REQUEST))
               node = this.findNodeByNameNS(result, "CancelTarget", WSTrustConstants.BASE_NAMESPACE);
            if(node == null)
               throw new RuntimeException("Unsupported request type:" + requestType);
            node.appendChild(result.importNode(targetElement, true));
         }
      }
      catch (Exception e)
      {
         throw new RuntimeException("Failed to marshall security token request", e);
      }

      return DocumentUtil.getXMLSource(result);
   }

   /**
    * <p>
    * Creates a {@code javax.xml.transform.Source} from the specified response object.
    * </p>
    * 
    * @param collection
    *           a {@code RequestSecurityTokenResponseCollection} representing the object model of the security token
    *           response.
    * @return the constructed {@code Source} instance.
    */
   public Source marshallRequestSecurityTokenResponse(RequestSecurityTokenResponseCollection collection)
   {
      if (collection.getRequestSecurityTokenResponses().size() == 0)
         throw new IllegalArgumentException("The response collection must contain at least one response");

      // if the response contains an issued token, we must preserve it from the JAXB marshaling.
      Element tokenElement = null;
      RequestSecurityTokenResponse response = collection.getRequestSecurityTokenResponses().get(0);
      if (response.getRequestedSecurityToken() != null)
      {
         tokenElement = (Element) response.getRequestedSecurityToken().getAny();
         // we don't want to marshall any token - it will be inserted in the DOM document later.
         response.getRequestedSecurityToken().setAny(null);
      }

      Document result = null;
      try
      {
         // marshall the response to a document and insert the issued token directly on the document.
         result = DocumentUtil.createDocument();
         this.marshaller.marshal(this.objectFactory.createRequestSecurityTokenResponseCollection(collection
               .getDelegate()), result);

         // the document is a ws-trust template - we need to insert the token in the appropriate element.
         if (tokenElement != null)
         {
            Node node = this.findNodeByNameNS(result, "RequestedSecurityToken", WSTrustConstants.BASE_NAMESPACE);
            node.appendChild(result.importNode(tokenElement, true));
         }
         if(trace)
         {
            log.trace("Final RSTR doc:" + DocumentUtil.asString(result)); 
         }
            
      }
      catch (Exception e)
      {
         throw new RuntimeException("Failed to marshall security token response", e);
      }
      return DocumentUtil.getXMLSource(result);
   }
   
   /**
    * Return the {@code SAMLDocumentHolder} for the thread
    * @return
    */
   public SAMLDocumentHolder getSAMLDocumentHolderOnThread()
   {
      return holders.get();
   }

   /**
    * <p>
    * Finds in the specified document a node that matches the specified name and namespace.
    * </p>
    * 
    * @param document
    *           the {@code Document} instance upon which the search is made.
    * @param localName
    *           a {@code String} containing the local name of the searched node.
    * @param namespace
    *           a {@code String} containing the namespace of the searched node.
    * @return a {@code Node} representing the searched node. If more than one node is found in the document, the first
    *         one will be returned. If no nodes were found according to the search parameters, then {@code null} is
    *         returned.
    */
   private Node findNodeByNameNS(Document document, String localName, String namespace)
   {
      NodeList list = document.getElementsByTagNameNS(namespace, localName);
      if (list == null || list.getLength() == 0)
         // log("Unable to locate element " + localName + " with namespace " + namespace);
         return null;
      return list.item(0);
   }

   /**
    * <p>
    * Searches the specified document for an element that represents a validate, renew, or cancel target.
    * </p>
    * 
    * @param document
    *           the {@code Document} upon which the search is to be made.
    * @return an {@code Element} representing the validate, renew, or cancel target.
    */
   /*private Element getValidateOrRenewOrCancelTarget(Document document)
   {
      Node target = this.findNodeByNameNS(document, "ValidateTarget", WSTrustConstants.BASE_NAMESPACE);
      if (target != null)
         return (Element) target.getFirstChild();
      target = this.findNodeByNameNS(document, "RenewTarget", WSTrustConstants.BASE_NAMESPACE);
      if (target != null)
         return (Element) target.getFirstChild();
      target = this.findNodeByNameNS(document, "CancelTarget", WSTrustConstants.BASE_NAMESPACE);
      if (target != null)
         return (Element) target.getFirstChild();
      return null;
   }*/
}