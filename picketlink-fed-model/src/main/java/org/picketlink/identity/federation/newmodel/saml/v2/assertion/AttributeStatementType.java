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

package org.picketlink.identity.federation.newmodel.saml.v2.assertion;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;



/**
 * <p>Java class for AttributeStatementType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="AttributeStatementType">
 *   &lt;complexContent>
 *     &lt;extension base="{urn:oasis:names:tc:SAML:2.0:assertion}StatementAbstractType">
 *       &lt;choice maxOccurs="unbounded">
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:assertion}Attribute"/>
 *         &lt;element ref="{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedAttribute"/>
 *       &lt;/choice>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */ 
public class AttributeStatementType
extends StatementAbstractType
{ 
   private static final long serialVersionUID = 1L;
   protected List<ASTChoiceType> attributes = new ArrayList<ASTChoiceType>();

   public void addAttribute( ASTChoiceType attribute )
   {
      attributes.add( attribute );
   }

   /**
    * Gets the attributes. 
    */
   public List<ASTChoiceType> getAttributes() 
   {
      return Collections.unmodifiableList( this.attributes );
   }

   public static class ASTChoiceType
   {
      private AttributeType attribute;
      private EncryptedElementType encryptedAssertion;

      public ASTChoiceType(AttributeType attribute)
      {
         super();
         this.attribute = attribute;
      }
      public ASTChoiceType(EncryptedElementType encryptedAssertion)
      {
         super();
         this.encryptedAssertion = encryptedAssertion;
      }
      public AttributeType getAttribute()
      {
         return attribute;
      }
      public EncryptedElementType getEncryptedAssertion()
      {
         return encryptedAssertion;
      } 
   }
}