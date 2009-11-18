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
package org.jboss.identity.federation.api.wstrust;

import org.jboss.identity.federation.core.exceptions.ParsingException;
import org.jboss.identity.federation.core.wstrust.STSClient;
import org.jboss.identity.federation.core.wstrust.STSClientConfig;
import org.jboss.identity.federation.core.wstrust.STSClientFactory;
import org.jboss.identity.federation.core.wstrust.WSTrustException;
import org.jboss.identity.federation.core.wstrust.STSClientConfig.Builder;
import org.w3c.dom.Element;

/**
 * WS-Trust Client
 * 
 * @author Anil.Saldhana@redhat.com
 * @since Aug 29, 2009
 */
public class WSTrustClient
{
    /**
     * The STSClient that this class delegates to.
     */
    private STSClient stsClient;
    
    public static class SecurityInfo
    {
        private String username;
        private String passwd;

        public SecurityInfo(String name, char[] pass)
        {
            username = name;
            passwd = new String(pass);
        }

        public SecurityInfo(String name, String pass)
        {
            username = name;
            passwd = pass;
        }
    }

    public WSTrustClient(String serviceName, String port, String endpointURI, SecurityInfo secInfo) throws ParsingException
    {
        Builder builder = new STSClientConfig.Builder();
        builder.serviceName(serviceName).portName(port).endpointAddress(endpointURI).username(secInfo.username).password(secInfo.passwd);
        stsClient = STSClientFactory.getInstance().create(builder.build());
    }

    /**
     * This method will send a RequestSecurityToken with a RequestType of issue
     * and the passed-in tokenType identifies the type of token to be issued by
     * the STS.
     * 
     * @param tokenType - The type of token to be issued.
     * @return Element - The Security Token element. Will be of the tokenType specified.
     * @throws WSTrustException
     */
    public Element issueToken(String tokenType) throws WSTrustException
    {
        return stsClient.issueToken(tokenType);
    }
    
    /**
     * This method will send a RequestSecurityToken with a RequestType of issue
     * and the passed-in endpointURI identifies the ultimate recipient of the token.
     * 
     * @param endpointURI - The ultimate recipient of the token. This will be set at the AppliesTo for
     *                      the RequestSecurityToken which is an optional element so it may be null.
     * @return Element - The Security Token element. Will be of the tokenType configured for the endpointURI.
     * @throws WSTrustException
     */
    public Element issueTokenForEndpoint(String endpointURI) throws WSTrustException
    {
        return stsClient.issueTokenForEndpoint(endpointURI);
    }
    
    /**
     * Issues a Security Token from the STS. This methods has the option of 
     * specifying both or one of endpointURI/tokenType but at least one must 
     * specified.
     * 
     * @param endpointURI - The ultimate recipient of the token. This will be set at the AppliesTo for
     *                      the RequestSecurityToken which is an optional element so it may be null.
     * @param tokenType - The type of security token to be issued.
     * @return Element - The Security Token Element issued.
     * @throws IllegalArgumentException If neither endpointURI nor tokenType was specified.
     * @throws WSTrustException
     */
    public Element issueToken(String endpointURI, String tokenType) throws WSTrustException
    {
        return stsClient.issueToken(endpointURI, tokenType);
    }
    
    /**
     * This method will send a RequestSecurityToken with a RequestType of renew
     * and the passed-in tokenType identifies the type of token to be renewed by 
     * the STS.
     * 
     * @param tokenType - The type of token to be renewed.
     * @param token - The security token to be renewed.
     * @return Element - The Security Token element. Will be of the tokenType specified.
     */
    public Element renewToken(String tokenType, Element token) throws WSTrustException
    {
        return stsClient.renewToken(tokenType, token);
    }

    /**
     * This method will send a RequestSecurityToken with a RequestType of validated by
     * the STS.
     * 
     * @param token - The security token to be validated.
     * @return true - If the security token was sucessfully valiated.
     */
    public boolean validateToken(Element token) throws WSTrustException
    {
        return stsClient.validateToken(token);
    }

}