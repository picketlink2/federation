package org.picketlink.identity.federation.newmodel.saml.v2.metadata;



/**
 * <p>Java class for KeyTypes.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="KeyTypes">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="encryption"/>
 *     &lt;enumeration value="signing"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
public enum KeyTypes 
{
   ENCRYPTION("encryption"),
   SIGNING("signing");
   private final String value;

   KeyTypes(String v) {
      value = v;
   }

   public String value() {
      return value;
   }

   public static KeyTypes fromValue(String v) {
      for (KeyTypes c: KeyTypes.values()) {
         if (c.value.equals(v)) {
            return c;
         }
      }
      throw new IllegalArgumentException(v);
   }
}