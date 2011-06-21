package org.picketlink.identity.federation.saml.v2.metadata;



/**
 * <p>Java class for localizedNameType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="localizedNameType">
 *   &lt;simpleContent>
 *     &lt;extension base="&lt;http://www.w3.org/2001/XMLSchema>string">
 *       &lt;attribute ref="{http://www.w3.org/XML/1998/namespace}lang use="required""/>
 *     &lt;/extension>
 *   &lt;/simpleContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
public class LocalizedNameType 
{
   protected String value;
   protected String lang;


   public LocalizedNameType(String lang)
   { 
      this.lang = lang;
   }

   /**
    * Gets the value of the value property.
    * 
    * @return
    *     possible object is
    *     {@link String }
    *     
    */
   public String getValue() {
      return value;
   }

   /**
    * Sets the value of the value property.
    * 
    * @param value
    *     allowed object is
    *     {@link String }
    *     
    */
   public void setValue(String value) {
      this.value = value;
   }

   /**
    * Gets the value of the lang property.
    * 
    * @return
    *     possible object is
    *     {@link String }
    *     
    */
   public String getLang() {
      return lang;
   } 
}
