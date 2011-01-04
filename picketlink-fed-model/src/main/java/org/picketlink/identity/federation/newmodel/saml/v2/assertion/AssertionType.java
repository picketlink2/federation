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

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

import javax.xml.datatype.XMLGregorianCalendar;
 
import org.w3c.dom.Element;

/**
 <complexType name="AssertionType">
        <sequence>
            <element ref="saml:Issuer"/>
            <element ref="ds:Signature" minOccurs="0"/>
            <element ref="saml:Subject" minOccurs="0"/>
            <element ref="saml:Conditions" minOccurs="0"/>
            <element ref="saml:Advice" minOccurs="0"/>
            <choice minOccurs="0" maxOccurs="unbounded">
                <element ref="saml:Statement"/>
                <element ref="saml:AuthnStatement"/>
                <element ref="saml:AuthzDecisionStatement"/>
                <element ref="saml:AttributeStatement"/>
            </choice>
        </sequence>
        <attribute name="Version" type="string" use="required"/>
        <attribute name="ID" type="ID" use="required"/>
        <attribute name="IssueInstant" type="dateTime" use="required"/>
    </complexType>
 * @author Anil.Saldhana@redhat.com
 * @since Nov 24, 2010
 */
public class AssertionType implements Serializable
{ 
   private static final long serialVersionUID = 1L;

   private String ID;

   private Element signature;

   private XMLGregorianCalendar issueInstant;

   private String version;

   private AdviceType advice;

   private NameIDType issuer;
   
   private SubjectType subject;

   private ConditionsType conditions;

   private Set<StatementAbstractType> statements = new LinkedHashSet<StatementAbstractType>();

   public AssertionType(String iD, XMLGregorianCalendar issueInstant, String version)
   { 
      this.ID = iD;
      this.issueInstant = issueInstant;
      this.version = version;
   }

   public String getID()
   {
      return ID;
   }

   public SubjectType getSubject()
   {
      return subject;
   }

   public void setSubject(SubjectType subject)
   {
      this.subject = subject;
   }

   public XMLGregorianCalendar getIssueInstant()
   {
      return issueInstant;
   }

   public String getVersion()
   {
      return version;
   }   

   public AdviceType getAdvice()
   {
      return advice;
   }

   public void setAdvice(AdviceType advice)
   {
      this.advice = advice;
   }

   public ConditionsType getConditions()
   {
      return conditions;
   }

   public void setConditions(ConditionsType conditions)
   {
      this.conditions = conditions;
   }

   public NameIDType getIssuer()
   {
      return issuer;
   }

   public void setIssuer(NameIDType issuer)
   {
      this.issuer = issuer;
   } 

   public void addStatement( StatementAbstractType statement )
   {
      this.statements.add( statement );
   }
   public void addStatements( Collection<StatementAbstractType> statement )
   {
      this.statements.addAll( statement );
   }

   public Set<StatementAbstractType> getStatements()
   {
      return Collections.unmodifiableSet( statements );
   }

   public Element getSignature()
   {
      return signature;
   }

   public void setSignature(Element signature)
   {
      this.signature = signature;
   } 
   
   public void updateIssueInstant( XMLGregorianCalendar xg )
   {
      SecurityManager sm = System.getSecurityManager();
      if( sm != null )
         sm.checkPermission( new RuntimePermission( "org.picketlink.sts") );
      
      this.issueInstant = xg; 
   }
}