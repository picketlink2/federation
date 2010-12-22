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

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.Certificate;

import org.picketlink.identity.federation.core.interfaces.SecurityTokenProvider;

/**
 * <p>
 * The {@code STSConfiguration} interface allows access to the security token service (STS) configuration attributes.
 * </p>
 * 
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * @author Anil.Saldhana@redhat.com
 */
public interface STSConfiguration
{

   /**
    * <p>
    * Obtains the unique name of the secure token service.
    * </p>
    * 
    * @return a {@code String} representing the STS name.
    */
   public String getSTSName();

   /**
    * <p>
    * Indicates whether the issued token should be encrypted or not.
    * </p>
    * 
    * @return {@code true} if the issued token is to be encrypted; {@code false} otherwise.
    */
   public boolean encryptIssuedToken();

   /**
    * <p>
    * Indicates whether the issued token should be digitally signed or not.
    * </p>
    * 
    * @return {@code true} if the issued token is to be signed; {@code false} otherwise.
    */
   public boolean signIssuedToken();

   /**
    * <p>
    * Obtains the timeout value (in milliseconds) for issued tokens.
    * </p>
    * 
    * @return the token timeout value.
    */
   public long getIssuedTokenTimeout();

   /**
    * <p>
    * Obtains the WS-Trust request handler class.
    * </p>
    * 
    * @return a reference to the configured {@code WSTrustRequestHandler}.
    */
   public WSTrustRequestHandler getRequestHandler();

   /**
    * <p>
    * Given the name of a service provider, obtains the type of the token that should be used when issuing tokens to
    * clients of that service.
    * </p>
    * 
    * @param serviceName the name of the service provider that requires a token from its clients.
    * @return a {@code String} representing the type of the token that suits the specified service.
    */
   public String getTokenTypeForService(String serviceName);

   /**
    * <p>
    * Given the name of a service provider, obtains the provider that must be used when issuing tokens to clients of
    * that service. When requesting a token to the STS, a client can specify the service it needs the token for using
    * the {@code AppliesTo} element. Based on the service provider name, the STS identifies the type of the token that
    * is to be issued and then selects the appropriate token provider to handle the request.
    * </p>
    * 
    * @param serviceName the name of the service provider that requires a token from its clients.
    * @return a reference to the {@code SecurityTokenProvider} that must be used in order to issue tokens to clients of
    *         the specified service.
    */
   public SecurityTokenProvider getProviderForService(String serviceName);

   /**
    * <p>
    * Given a token type, obtains the token provider that should be used to handle token requests of that type. When a
    * client doesn't specify the service provider name through the {@code AppliesTo} element, it must specify the token
    * type through the {@code TokenType} element. The STS uses the supplied type to select the appropriate token
    * provider.
    * </p>
    * 
    * @param tokenType a {@code String} representing the type of the token.
    * @return a reference to the {@code SecurityTokenProvider} that must be used to handle token requests of the
    *         specified type.
    */
   public SecurityTokenProvider getProviderForTokenType(String tokenType);

   /**
    * <p>
    * Obtains the token provider that can handle tokens that have the specified local name and namespace. When a
    * validate, renew, or cancel request is made, the token type is not set in the WS-Trust request. In these cases
    * the {@code SecurityTokenProvider} must be determined using the security token itself.
    * </p>
    * 
    * @param tokenLocalName a {@code String} representing the token element name. (e.g. {@code Assertion}).
    * @param tokenNamespace a {@code String} representing the token element namespace. (e.g.
    *   {@code urn:oasis:names:tc:SAML:2.0:assertion}).
    * @return a reference to the {@code SecurityTokenProvider} that must be used to handle the request that contains
    * only the security token.
    */
   public SecurityTokenProvider getProviderForTokenElementNS(String tokenLocalName, String tokenNamespace);

   /**
    * <p>
    * Obtains the {@code ClaimsProcessor} that must be used to handle claims of the specified dialect.
    * </p>
    * 
    * @param claimsDialect a {@code String} representing the claims dialect (usually a URL).
    * @return the {@code ClaimsProcessor} to be used, or {@code null} if no processor could be found for the dialect.
    */
   public ClaimsProcessor getClaimsProcessor(String claimsDialect);
   
   /**
    * <p>
    * Obtains a reference to the {@code KeyPair} object that contains the STS {@code PrivateKey} and {@code PublicKey}.
    * </p>
    * 
    * @return a reference to the STS {@code KeyPair}.
    */
   public KeyPair getSTSKeyPair();

   /**
    * <p>
    * Obtains the public key of the specified service provider. The returned key is used to encrypt issued tokens.
    * </p>
    * 
    * @param serviceName the name of the service provider (normally the provider URL).
    * @return a reference to the provider's {@code PublicKey}
    */
   public PublicKey getServiceProviderPublicKey(String serviceName);
   
   /**
    * <p>
    * Obtains the certificate identified by the specified alias.
    * </p>
    * 
    * @param alias the alias associated with the certificate in the keystore.
    * @return the {@code Certificate} obtained from the keystore, or {@code null} if no certificate was found.
    */
   public Certificate getCertificate(String alias);
   
   /**
    * <p>
    * Returns the configured canonicalization method.
    * </p>
    * <p>
    * <b>NOTE:</b> Defaults to javax.xml.crypto.dsig.CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS
    * </p>
    * @return
    */
   public String getXMLDSigCanonicalizationMethod();
}