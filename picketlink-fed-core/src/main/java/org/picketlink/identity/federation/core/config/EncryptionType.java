package org.picketlink.identity.federation.core.config;
 

/**
 * <p>Java class for EncryptionType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="EncryptionType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="EncAlgo" type="{urn:picketlink:identity-federation:config:1.0}EncAlgoType"/>
 *         &lt;element name="KeySize" type="{http://www.w3.org/2001/XMLSchema}int"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */ 
public class EncryptionType {
 
    protected EncAlgoType encAlgo; 
    protected int keySize;

    /**
     * Gets the value of the encAlgo property.
     * 
     * @return
     *     possible object is
     *     {@link EncAlgoType }
     *     
     */
    public EncAlgoType getEncAlgo() {
        return encAlgo;
    }

    /**
     * Sets the value of the encAlgo property.
     * 
     * @param value
     *     allowed object is
     *     {@link EncAlgoType }
     *     
     */
    public void setEncAlgo(EncAlgoType value) {
        this.encAlgo = value;
    }

    /**
     * Gets the value of the keySize property.
     * 
     */
    public int getKeySize() {
        return keySize;
    }

    /**
     * Sets the value of the keySize property.
     * 
     */
    public void setKeySize(int value) {
        this.keySize = value;
    }

}
