


package org.picketlink.identity.federation.newmodel.saml.v2.metadata;

import org.picketlink.identity.federation.newmodel.saml.v2.assertion.AttributeType;


/**
 * <p>Java class for RequestedAttributeType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="RequestedAttributeType">
 *   &lt;complexContent>
 *     &lt;extension base="{urn:oasis:names:tc:SAML:2.0:assertion}AttributeType">
 *       &lt;attribute name="isRequired" type="{http://www.w3.org/2001/XMLSchema}boolean" />
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
public class RequestedAttributeType
extends AttributeType
{

   public RequestedAttributeType(String name)
   {
      super(name); 
   }

   protected Boolean isRequired;

   /**
    * Gets the value of the isRequired property.
    * 
    * @return
    *     possible object is
    *     {@link Boolean }
    *     
    */
   public Boolean isIsRequired() 
   {
      return isRequired;
   }

   /**
    * Sets the value of the isRequired property.
    * 
    * @param value
    *     allowed object is
    *     {@link Boolean }
    *     
    */
   public void setIsRequired(Boolean value) 
   {
      this.isRequired = value;
   }
}