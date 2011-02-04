package org.picketlink.identity.federation.core.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 
 * 				The claims processors specify the classes that are capable of processing specific claims dialects.
 * 			
 * 
 * <p>Java class for ClaimsProcessorsType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ClaimsProcessorsType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="ClaimsProcessor" type="{urn:picketlink:identity-federation:config:1.0}ClaimsProcessorType" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */ 
public class ClaimsProcessorsType {

    protected List<ClaimsProcessorType> claimsProcessor = new ArrayList<ClaimsProcessorType>();

    public void add( ClaimsProcessorType claim )
    {
       this.claimsProcessor.add( claim);
    }
    
    public void remove( ClaimsProcessorType claim )
    {
       this.claimsProcessor.remove( claim);
    }
    
    /**
     * Gets the value of the claimsProcessor property.
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link ClaimsProcessorType }
     * 
     * 
     */
    public List<ClaimsProcessorType> getClaimsProcessor() { 
        return Collections.unmodifiableList( this.claimsProcessor );
    }

}