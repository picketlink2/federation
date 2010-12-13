package org.picketlink.identity.federation.newmodel.saml.v2.metadata;



/**
 * <p>Java class for ContactTypeType.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="ContactTypeType">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="technical"/>
 *     &lt;enumeration value="support"/>
 *     &lt;enumeration value="administrative"/>
 *     &lt;enumeration value="billing"/>
 *     &lt;enumeration value="other"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */ 
public enum ContactTypeType 
{
   TECHNICAL("technical"),
   SUPPORT("support"),
   ADMINISTRATIVE("administrative"),
   BILLING("billing"),
   OTHER("other");
   private final String value;

   ContactTypeType(String v) {
      value = v;
   }

   public String value() {
      return value;
   }

   public static ContactTypeType fromValue(String v) {
      for (ContactTypeType c: ContactTypeType.values()) {
         if (c.value.equals(v)) {
            return c;
         }
      }
      throw new IllegalArgumentException(v);
   }

}
