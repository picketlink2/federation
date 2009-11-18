/*
 * JBoss, Home of Professional Open Source Copyright 2009, Red Hat Middleware
 * LLC, and individual contributors by the @authors tag. See the copyright.txt
 * in the distribution for a full listing of individual contributors.
 * 
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 * 
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA, or see the FSF
 * site: http://www.fsf.org.
 */
package org.picketlink.identity.federation.core.wstrust.handlers;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import javax.xml.namespace.QName;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import javax.xml.soap.SOAPMessage;
import javax.xml.ws.WebServiceException;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import junit.framework.TestCase;

import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.wstrust.STSClient;
import org.picketlink.identity.federation.core.wstrust.STSClientConfig.Builder;
import org.picketlink.identity.federation.core.wstrust.handlers.STSSaml20Handler;
import org.picketlink.identity.federation.core.wstrust.handlers.STSSecurityHandler;
import org.w3c.dom.Element;

/**
 * Unit test for {@link STSSaml20Handler}.
 * 
 * @author <a href="mailto:dbevenius@jboss.com">Daniel Bevenius</a>
 * 
 */
public class STSSaml20HandlerTestCase extends TestCase
{
    private SOAPMessageContext soapMessageContext;
    private SOAPMessage soapMessage;
    private STSClient wsTrustClient;
    private STSSaml20Handler samlHandler;
    
    public void testHandleMessageOutbound() 
    {
        setOutbound(soapMessageContext, true);
        assertTrue(new STSSaml20Handler().handleMessage(soapMessageContext));
    }
    
    public void testHandleMessageInboundValidToken() throws Exception
    {
        final SOAPHeader soapHeader = soapMessage.getSOAPHeader();
        
        // Make the Mocked WSTrustClient validateToken method return true.
        when(wsTrustClient.validateToken((any(Element.class)))).thenReturn(true);
        
        final SOAPHeaderElement securityHeader = addSecurityHeader(samlHandler, soapHeader);
        addAssertionElement(samlHandler, securityHeader);
        
        setOutbound(soapMessageContext, false);
        setMessageOnContext(soapMessageContext, soapMessage);
        
        boolean result = samlHandler.handleMessage(soapMessageContext);
        assertTrue(result);
    }
    
    public void testHandleMessageInValidToken() throws Exception
    {
        final SOAPHeader soapHeader = soapMessage.getSOAPHeader();
        
        // Make the Mocked WSTrustClient validateToken method return false.
        when(wsTrustClient.validateToken((any(Element.class)))).thenReturn(false);
        
        final SOAPHeaderElement securityHeader = addSecurityHeader(samlHandler, soapHeader);
        addAssertionElement(samlHandler, securityHeader);

        setOutbound(soapMessageContext, false);
        setMessageOnContext(soapMessageContext, soapMessage);
        try
        {
            samlHandler.handleMessage(soapMessageContext);
            fail("handleMessage should have thrown a exception!");
        }
        catch(final Exception e)
        {
            assertTrue (e instanceof WebServiceException);
        }
    }
    
    public void testUsernamePasswordFromSOAPMessageContext() throws Exception
    {
        final SOAPHeader soapHeader = soapMessage.getSOAPHeader();
        
        // Make the Mocked WSTrustClient validateToken method return true.
        when(wsTrustClient.validateToken((any(Element.class)))).thenReturn(true);
        final SOAPHeaderElement securityHeader = addSecurityHeader(samlHandler, soapHeader);
        addAssertionElement(samlHandler, securityHeader);
        
        setOutbound(soapMessageContext, false);
        setMessageOnContext(soapMessageContext, soapMessage);
        
        when(soapMessageContext.get(STSSecurityHandler.USERNAME_MSG_CONTEXT_PROPERTY)).thenReturn("Fletch");
        when(soapMessageContext.get(STSSecurityHandler.PASSWORD_MSG_CONTEXT_PROPERTY)).thenReturn("letmein");
        
        samlHandler.handleMessage(soapMessageContext);
        
        assertEquals("Fletch", samlHandler.getConfigBuilder().getUsername());
        assertEquals("letmein", samlHandler.getConfigBuilder().getPassword());
    }

    @Override
    public void setUp()
    {
        // Create a Mock for WSTrustClient.
        wsTrustClient = mock(STSClient.class);
        
        samlHandler = new FakeSamlHandler(wsTrustClient);
        samlHandler.setConfigFile("wstrust/auth/jboss-sts-client.properties");
        // Simulate the WS Engine calling @PostConstruct.
        samlHandler.parseSTSConfig();
        
        soapMessageContext = mock(SOAPMessageContext.class);
        
        try
        {
            soapMessage = MessageFactory.newInstance().createMessage();
        }
        catch (SOAPException e)
        {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }
    
    private class FakeSamlHandler extends STSSaml20Handler
    {
        private final STSClient stsClient;

        public FakeSamlHandler(final STSClient stsClient)
        {
            this.stsClient = stsClient;
        }

        @Override
        protected STSClient createSTSClient(Builder builder) throws ParsingException
        {
            return stsClient;
        }
    }
    
    private SOAPHeaderElement addSecurityHeader(final STSSecurityHandler handler, final SOAPHeader soapHeader) throws SOAPException
    {
        final QName securityQName = handler.getSecurityElementQName();
        final SOAPHeaderElement securityHeader = soapHeader.addHeaderElement(new QName(securityQName.getNamespaceURI(), securityQName.getLocalPart(), "wsse"));
        soapHeader.addChildElement(securityHeader);
        return securityHeader;
    }

    private SOAPElement addAssertionElement(final STSSecurityHandler handler, final SOAPHeaderElement securityHeader) throws SOAPException
    {
        final QName tokenElementQName = handler.getTokenElementQName();
        final SOAPElement tokenElement = securityHeader.addChildElement(new QName(tokenElementQName.getNamespaceURI(), tokenElementQName.getLocalPart(), "saml"));
        return securityHeader.addChildElement(tokenElement);
    }

    private void setMessageOnContext(final SOAPMessageContext messageContext, final SOAPMessage soapMessage)
    {
        when(messageContext.getMessage()).thenReturn(soapMessage);
    }
    
    private void setOutbound(MessageContext messageContext, boolean outbound)
    {
        when(messageContext.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY)).thenReturn(outbound);
    }

}

