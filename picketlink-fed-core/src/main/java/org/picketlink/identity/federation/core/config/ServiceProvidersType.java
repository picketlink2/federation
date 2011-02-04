package org.picketlink.identity.federation.core.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List; 

/**
 * 
 * 				The service providers specify the token type expected by each service provider.
 * 			
 * 
 * <p>Java class for ServiceProvidersType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ServiceProvidersType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="ServiceProvider" type="{urn:picketlink:identity-federation:config:1.0}ServiceProviderType" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */ 
public class ServiceProvidersType {
 
    protected List<ServiceProviderType> serviceProvider = new ArrayList<ServiceProviderType>();

    public void add( ServiceProviderType sp )
    {
       this.serviceProvider.add(sp);
    }
    
    public void remove( ServiceProviderType sp )
    {
       this.serviceProvider.remove(sp);
    }
    
    /**
     * Gets the value of the serviceProvider property.
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link ServiceProviderType }
     * 
     * 
     */
    public List<ServiceProviderType> getServiceProvider() { 
        return Collections.unmodifiableList( this.serviceProvider );
    }

}