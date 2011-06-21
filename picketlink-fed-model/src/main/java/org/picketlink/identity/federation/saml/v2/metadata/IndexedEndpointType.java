package org.picketlink.identity.federation.saml.v2.metadata;

import java.net.URI;



/**
 * <p>Java class for IndexedEndpointType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="IndexedEndpointType">
 *   &lt;complexContent>
 *     &lt;extension base="{urn:oasis:names:tc:SAML:2.0:metadata}EndpointType">
 *       &lt;attribute name="index" use="required" type="{http://www.w3.org/2001/XMLSchema}unsignedShort" />
 *       &lt;attribute name="isDefault" type="{http://www.w3.org/2001/XMLSchema}boolean" />
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */ 
public class IndexedEndpointType
extends EndpointType
{

   protected int index; 
   protected Boolean isDefault;

   public IndexedEndpointType(URI binding, URI location)
   {
      super(binding, location);
   }

   /**
    * Gets the value of the index property.
    * 
    */
   public int getIndex() {
      return index;
   }

   /**
    * Sets the value of the index property.
    * 
    */
   public void setIndex(int value) {
      this.index = value;
   }

   /**
    * Gets the value of the isDefault property.
    * 
    * @return
    *     possible object is
    *     {@link Boolean }
    *     
    */
   public Boolean isIsDefault() {
      return isDefault;
   }

   /**
    * Sets the value of the isDefault property.
    * 
    * @param value
    *     allowed object is
    *     {@link Boolean }
    *     
    */
   public void setIsDefault(Boolean value) {
      this.isDefault = value;
   }
}