package org.picketlink.identity.federation.core.config;

/**
 * <p>Java class for EncAlgoType.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="EncAlgoType">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="AES"/>
 *     &lt;enumeration value="DES"/>
 *     &lt;enumeration value="DESede"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */ 
public enum EncAlgoType {

    AES("AES"),
    DES("DES"), 
    DE_SEDE("DESede");
    private final String value;

    EncAlgoType(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static EncAlgoType fromValue(String v) {
        for (EncAlgoType c: EncAlgoType.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
