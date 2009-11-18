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
package org.jboss.test.identity.federation.core.config;

import java.io.InputStream;
import java.util.List;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;

import junit.framework.TestCase;

import org.jboss.identity.federation.core.config.AuthPropertyType;
import org.jboss.identity.federation.core.config.IDPType;
import org.jboss.identity.federation.core.config.KeyProviderType;
import org.jboss.identity.federation.core.config.KeyValueType;
import org.jboss.identity.federation.core.config.SPType;
import org.jboss.identity.federation.core.config.STSType;
import org.jboss.identity.federation.core.config.ServiceProviderType;
import org.jboss.identity.federation.core.config.ServiceProvidersType;
import org.jboss.identity.federation.core.config.TokenProviderType;
import org.jboss.identity.federation.core.config.TokenProvidersType;
import org.jboss.identity.federation.core.config.TrustType;
import org.jboss.identity.federation.core.handler.config.Handler;
import org.jboss.identity.federation.core.handler.config.Handlers;
import org.jboss.identity.federation.core.util.JAXBUtil;

/**
 * Unit Test the various config
 * 
 * @author Anil.Saldhana@redhat.com
 * @since Jan 21, 2009
 */
public class ConfigUnitTestCase extends TestCase
{
   String config = "config/test-config-";

   @SuppressWarnings("unchecked")
   public void test01() throws Exception
   {
      Object object = this.unmarshall(config + "1.xml");
      assertNotNull("IDP is not null", object);
      assertTrue(object instanceof JAXBElement);

      IDPType idp = ((JAXBElement<IDPType>) object).getValue();
      assertEquals("300000", 300000L, idp.getAssertionValidity());
      assertEquals("org.jboss.identity.federation.bindings.tomcat.TomcatRoleGenerator", idp.getRoleGenerator());

      TrustType trust = idp.getTrust();
      assertNotNull("Trust is not null", trust);
      String domains = trust.getDomains();
      assertTrue("localhost trusted", domains.indexOf("localhost") > -1);
      assertTrue("jboss.com trusted", domains.indexOf("jboss.com") > -1);
   }

   @SuppressWarnings("unchecked")
   public void test02() throws Exception
   {
      Object object = this.unmarshall(config + "2.xml");
      assertNotNull("IDP is not null", object);
      assertTrue(object instanceof JAXBElement);

      IDPType idp = ((JAXBElement<IDPType>) object).getValue();
      assertEquals("20000", 20000L, idp.getAssertionValidity());
      assertEquals("somefqn", idp.getRoleGenerator());
      assertTrue(idp.isEncrypt());
      KeyProviderType kp = idp.getKeyProvider();
      assertNotNull("KeyProvider is not null", kp);
      assertEquals("SomeClass", "SomeClass", kp.getClassName());
      List<AuthPropertyType> authProps = kp.getAuth();
      AuthPropertyType authProp = authProps.get(0);
      assertEquals("SomeKey", "SomeKey", authProp.getKey());
      assertEquals("SomeValue", "SomeValue", authProp.getValue());

      authProp = authProps.get(1);
      assertEquals("DBURL", "DBURL", authProp.getKey());
      assertEquals("SomeDBURL", "SomeDBURL", authProp.getValue());

      List<KeyValueType> validatingAliases = kp.getValidatingAlias();
      assertEquals("Validating Alias length is 2", 2, validatingAliases.size());

      KeyValueType kv = validatingAliases.get(0);
      assertEquals("localhost", kv.getKey());
      assertEquals("localhostalias", kv.getValue());

      kv = validatingAliases.get(1);
      assertEquals("jboss.com", kv.getKey());
      assertEquals("jbossalias", kv.getValue());

      TrustType trust = idp.getTrust();
      assertNotNull("Trust is not null", trust);
      String domains = trust.getDomains();
      assertTrue("localhost trusted", domains.indexOf("localhost") > -1);
      assertTrue("jboss.com trusted", domains.indexOf("jboss.com") > -1);
   }

   @SuppressWarnings("unchecked")
   public void test03() throws Exception
   {
      Object object = this.unmarshall(config + "3.xml");
      assertNotNull("SP is null", object);
      assertTrue(object instanceof JAXBElement);

      SPType sp = ((JAXBElement<SPType>) object).getValue();
      assertEquals("http://localhost:8080/idp", sp.getIdentityURL());
      assertEquals("http://localhost:8080/sales", sp.getServiceURL());
   }

   /**
    * <p>
    * Tests the parsing of a Security Token Service configuration.
    * </p>
    * 
    * @throws Exception if an error occurs while running the test.
    */
   @SuppressWarnings("unchecked")
   public void test04() throws Exception
   {
      Object object = this.unmarshall(this.config + "4.xml");
      assertNotNull("Found a null STS configuration", object);
      assertTrue("Unexpected configuration type", object instanceof JAXBElement);

      STSType stsType = ((JAXBElement<STSType>) object).getValue();
      // general STS configurations.
      assertEquals("Unexpected STS name", "Test STS", stsType.getSTSName());
      assertEquals("Unexpected token timeout value", 7200, stsType.getTokenTimeout());
      assertTrue("Encryption of tokens should have been enabled", stsType.isEncryptToken());
      // we don't verify all values of the key provider config as it has been done in the other test scenarios.
      assertNotNull("Unexpected null key provider", stsType.getKeyProvider());
      // request handler and configurations based on the token type.
      assertEquals("Unexpected request handler class", "org.jboss.identity.federation.wstrust.Handler", stsType
            .getRequestHandler());
      // configuration of the token providers.
      TokenProvidersType tokenProviders = stsType.getTokenProviders();
      assertNotNull("Unexpected null list of token providers", tokenProviders);
      assertEquals("Unexpected number of token providers", 1, tokenProviders.getTokenProvider().size());
      TokenProviderType tokenProvider = tokenProviders.getTokenProvider().get(0);
      assertNotNull("Unexpected null token provider", tokenProvider);
      assertEquals("Unexpected provider class name", "org.jboss.SpecialTokenProvider", tokenProvider.getProviderClass());
      assertEquals("Unexpected token type", "specialToken", tokenProvider.getTokenType());
      assertEquals("Unexpected token element name", "SpecialToken", tokenProvider.getTokenElement());
      assertEquals("Unexpected token namespace", "http://www.tokens.org", tokenProvider.getTokenElementNS());
      List<KeyValueType> properties = tokenProvider.getProperty();
      assertEquals("Invalid number of properties", 2, properties.size());
      // configuration of the service providers.
      ServiceProvidersType serviceProviders = stsType.getServiceProviders();
      assertNotNull("Unexpected null list of service providers", serviceProviders);
      assertEquals("Unexpected number of service providers", 1, serviceProviders.getServiceProvider().size());
      ServiceProviderType serviceProvider = serviceProviders.getServiceProvider().get(0);
      assertNotNull("Unexpected null service provider", serviceProvider);
      assertEquals("Unexpected provider endpoint", "http://provider.endpoint/provider", serviceProvider.getEndpoint());
      assertEquals("Unexpected truststore alias", "providerAlias", serviceProvider.getTruststoreAlias());
      assertEquals("Unexpected token type", "specialToken", serviceProvider.getTokenType());
   }
   
   @SuppressWarnings("unchecked")
   public void test05() throws Exception
   {
      JAXBElement<Handlers> handlersJaxb = (JAXBElement<Handlers>) this.unmarshall(config + "5.xml"); 
      assertNotNull("Handlers not null", handlersJaxb); 

      Handlers handlers = handlersJaxb.getValue();
      List<Handler> handlerList = handlers.getHandler();
      assertEquals("1 handler",1, handlerList.size());
      
      Handler handler = handlerList.get(0);
      assertEquals("Class Name","a", handler.getClazz());
      List<KeyValueType> options = handler.getOption();
      assertEquals("2 options", 2, options.size());
      KeyValueType k1 = options.get(0);
      assertEquals("1", "1", k1.getKey());
      assertEquals("1.1", "1.1", k1.getValue());
      KeyValueType k2 = options.get(1);
      assertEquals("2", "2", k2.getKey());
      assertEquals("2.2", "2.2", k2.getValue());
   }

   private Object unmarshall(String configFile) throws Exception
   {
      String[] schemas = new String[] { "schema/config/jboss-identity-fed.xsd",
            "schema/config/jboss-identity-fed-handler.xsd"};

      ClassLoader tcl = Thread.currentThread().getContextClassLoader();
      InputStream is = tcl.getResourceAsStream(configFile);
      assertNotNull("Inputstream not null for config file:" + configFile, is);

      String[] pkgNames = new String[] {"org.jboss.identity.federation.core.config",
                                        "org.jboss.identity.federation.core.handler.config"};
      Unmarshaller un = JAXBUtil.getValidatingUnmarshaller(pkgNames,
            schemas);
      return un.unmarshal(is);
   }
}