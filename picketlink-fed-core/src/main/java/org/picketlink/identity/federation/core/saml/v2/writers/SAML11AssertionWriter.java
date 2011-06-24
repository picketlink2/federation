/*
 * JBoss, Home of Professional Open Source. Copyright 2008, Red Hat Middleware LLC, and individual contributors as
 * indicated by the @author tags. See the copyright.txt file in the distribution for a full listing of individual
 * contributors.
 * 
 * This is free software; you can redistribute it and/or modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either version 2.1 of the License, or (at your option) any
 * later version.
 * 
 * This software is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU Lesser General Public License along with this software; if not, write to
 * the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA, or see the FSF site:
 * http://www.fsf.org.
 */
package org.picketlink.identity.federation.core.saml.v2.writers;

import static org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants.ASSERTION_NSURI;

import java.net.URI;
import java.util.List;
import java.util.Set;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamWriter;

import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.saml.v1.SAML11Constants;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLConstants;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.core.util.StaxUtil;
import org.picketlink.identity.federation.core.util.StringUtil;
import org.picketlink.identity.federation.core.wstrust.WSTrustConstants;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11AdviceType;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11AssertionType;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11AttributeStatementType;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11AttributeType;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11AudienceRestrictionCondition;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11AuthenticationStatementType;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11AuthorizationDecisionStatementType;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11ConditionAbstractType;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11ConditionsType;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11NameIdentifierType;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11StatementAbstractType;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11SubjectType;
import org.picketlink.identity.federation.saml.v1.assertion.SAML11SubjectType.SAML11SubjectTypeChoice;
import org.picketlink.identity.federation.saml.v2.assertion.AuthnContextClassRefType;
import org.picketlink.identity.federation.saml.v2.assertion.AuthnContextDeclRefType;
import org.picketlink.identity.federation.saml.v2.assertion.AuthnContextDeclType;
import org.picketlink.identity.federation.saml.v2.assertion.AuthnContextType;
import org.picketlink.identity.federation.saml.v2.assertion.AuthnContextType.AuthnContextTypeSequence;
import org.picketlink.identity.federation.saml.v2.assertion.BaseIDAbstractType;
import org.picketlink.identity.federation.saml.v2.assertion.KeyInfoConfirmationDataType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.StatementAbstractType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectConfirmationDataType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectConfirmationType;
import org.picketlink.identity.federation.saml.v2.assertion.URIType;
import org.picketlink.identity.federation.saml.v2.profiles.xacml.assertion.XACMLAuthzDecisionStatementType;
import org.picketlink.identity.xmlsec.w3.xmldsig.KeyInfoType;
import org.picketlink.identity.xmlsec.w3.xmldsig.X509CertificateType;
import org.picketlink.identity.xmlsec.w3.xmldsig.X509DataType;
import org.w3c.dom.Element;

/**
 * Write the SAML 11 Assertion to stream
 * 
 * @author Anil.Saldhana@redhat.com
 * @since June 24, 2011
 */
public class SAML11AssertionWriter extends BaseWriter
{
   public SAML11AssertionWriter(XMLStreamWriter writer) throws ProcessingException
   {
      super(writer);
   }

   /**
    * Write an {@code SAML11AssertionType} to stream
    * 
    * @param assertion
    * @param out
    * @throws ProcessingException
    */
   public void write(SAML11AssertionType assertion) throws ProcessingException
   {
      String ns = SAML11Constants.ASSERTION_11_NSURI;
      StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.ASSERTION.get(), ns);
      StaxUtil.writeNameSpace(writer, ASSERTION_PREFIX, ns);
      StaxUtil.writeDefaultNameSpace(writer, ns);

      // Attributes
      StaxUtil.writeAttribute(writer, JBossSAMLConstants.ID.get(), assertion.getID());
      StaxUtil.writeAttribute(writer, SAML11Constants.MAJOR_VERSION, assertion.getMajorVersion() + "");
      StaxUtil.writeAttribute(writer, SAML11Constants.MINOR_VERSION, assertion.getMinorVersion() + "");
      StaxUtil.writeAttribute(writer, JBossSAMLConstants.ISSUE_INSTANT.get(), assertion.getIssueInstant().toString());

      String issuer = assertion.getIssuer();
      if (issuer != null)
      {
         StaxUtil.writeAttribute(writer, SAML11Constants.ISSUER, issuer);
      }

      SAML11ConditionsType conditions = assertion.getConditions();
      if (conditions != null)
      {
         StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.CONDITIONS.get(), ns);

         StaxUtil.writeAttribute(writer, JBossSAMLConstants.NOT_BEFORE.get(), conditions.getNotBefore().toString());
         StaxUtil.writeAttribute(writer, JBossSAMLConstants.NOT_ON_OR_AFTER.get(), conditions.getNotOnOrAfter()
               .toString());

         List<SAML11ConditionAbstractType> typeOfConditions = conditions.get();
         if (typeOfConditions != null)
         {
            for (SAML11ConditionAbstractType typeCondition : typeOfConditions)
            {
               if (typeCondition instanceof SAML11AudienceRestrictionCondition)
               {
                  SAML11AudienceRestrictionCondition art = (SAML11AudienceRestrictionCondition) typeCondition;
                  StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, SAML11Constants.AUDIENCE_RESTRICTION_CONDITION,
                        ns);
                  List<URI> audiences = art.get();
                  if (audiences != null)
                  {
                     for (URI audience : audiences)
                     {
                        StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.AUDIENCE.get(), ns);
                        StaxUtil.writeCharacters(writer, audience.toString());
                        StaxUtil.writeEndElement(writer);
                     }
                  }

                  StaxUtil.writeEndElement(writer);
               }
            }
         }

         StaxUtil.writeEndElement(writer);
      }

      SAML11AdviceType advice = assertion.getAdvice();
      if (advice != null)
         throw new RuntimeException("Advice needs to be handled");

      List<SAML11StatementAbstractType> statements = assertion.getStatements();
      if (statements != null)
      {
         for (SAML11StatementAbstractType statement : statements)
         {
            if (statement instanceof SAML11AuthenticationStatementType)
            {
               write((SAML11AuthenticationStatementType) statement);
            }
            else if (statement instanceof SAML11AttributeStatementType)
            {
               write((SAML11AttributeStatementType) statement);
            }
            else if (statement instanceof SAML11AuthorizationDecisionStatementType)
            {
               write((SAML11AuthorizationDecisionStatementType) statement);
            }
            else
               throw new RuntimeException("unknown statement type=" + statement.getClass().getName());
         }
      }

      StaxUtil.writeEndElement(writer);
      StaxUtil.flush(writer);
   }

   /**
    * Write an {@code StatementAbstractType} to stream
    * 
    * @param statement
    * @param out
    * @throws ProcessingException
    */
   public void write(StatementAbstractType statement) throws ProcessingException
   {
      // TODO: handle this section
      throw new RuntimeException("NYI");
   }

   public void write(SAML11AttributeStatementType statement) throws ProcessingException
   {
      StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.ATTRIBUTE_STATEMENT.get(),
            SAML11Constants.ASSERTION_11_NSURI);

      List<SAML11AttributeType> attributes = statement.get();
      if (attributes != null)
      {
         for (SAML11AttributeType attr : attributes)
         {
            throw new RuntimeException("NYI");
         }
      }

      StaxUtil.writeEndElement(writer);
      StaxUtil.flush(writer);
   }

   /**
    * Write an {@code AuthnStatementType} to stream
    * 
    * @param authnStatement
    * @param out
    * @throws ProcessingException
    */
   public void write(SAML11AuthenticationStatementType authnStatement) throws ProcessingException
   {
      StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.AUTHN_STATEMENT.get(),
            SAML11Constants.ASSERTION_11_NSURI);

      XMLGregorianCalendar authnInstant = authnStatement.getAuthenticationInstant();
      if (authnInstant != null)
      {
         StaxUtil.writeAttribute(writer, SAML11Constants.AUTHENTICATION_INSTANT, authnInstant.toString());
      }

      URI authMethod = authnStatement.getAuthenticationMethod();
      if (authMethod != null)
      {
         StaxUtil.writeAttribute(writer, SAML11Constants.AUTHENTICATION_METHOD, authMethod.toString());
      }

      StaxUtil.writeEndElement(writer);
      StaxUtil.flush(writer);
   }

   public void write(SAML11AuthorizationDecisionStatementType xacmlStat) throws ProcessingException
   {
      StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.STATEMENT.get(), ASSERTION_NSURI.get());

      StaxUtil.writeNameSpace(writer, ASSERTION_PREFIX, ASSERTION_NSURI.get());
      StaxUtil.writeNameSpace(writer, XACML_SAML_PREFIX, JBossSAMLURIConstants.XACML_SAML_NSURI.get());
      StaxUtil.writeNameSpace(writer, XACML_SAML_PROTO_PREFIX, JBossSAMLURIConstants.XACML_SAML_PROTO_NSURI.get());
      StaxUtil.writeNameSpace(writer, XSI_PREFIX, JBossSAMLURIConstants.XSI_NSURI.get());

      StaxUtil.writeAttribute(writer, new QName(JBossSAMLURIConstants.XSI_NSURI.get(), JBossSAMLConstants.TYPE.get(),
            XSI_PREFIX), XACMLAuthzDecisionStatementType.XSI_TYPE);

      StaxUtil.writeEndElement(writer);
      StaxUtil.flush(writer);
   }

   /**
    * Write an {@code AuthnContextType} to stream
    * 
    * @param authContext
    * @param out
    * @throws ProcessingException
    */
   public void write(AuthnContextType authContext) throws ProcessingException
   {
      StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.AUTHN_CONTEXT.get(),
            ASSERTION_NSURI.get());

      AuthnContextTypeSequence sequence = authContext.getSequence();
      if (sequence != null)
      {
         AuthnContextClassRefType authnContextClassRefType = sequence.getClassRef();
         if (authnContextClassRefType != null)
         {
            StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.AUTHN_CONTEXT_CLASS_REF.get(),
                  ASSERTION_NSURI.get());
            StaxUtil.writeCharacters(writer, authnContextClassRefType.getValue().toASCIIString());
            StaxUtil.writeEndElement(writer);
         }

         Set<URIType> uriTypes = sequence.getURIType();
         if (uriTypes != null)
         {
            for (URIType uriType : uriTypes)
            {
               if (uriType instanceof AuthnContextDeclType)
               {
                  StaxUtil.writeStartElement(writer, ASSERTION_PREFIX,
                        JBossSAMLConstants.AUTHN_CONTEXT_DECLARATION.get(), ASSERTION_NSURI.get());
                  StaxUtil.writeCharacters(writer, uriType.getValue().toASCIIString());
                  StaxUtil.writeEndElement(writer);
               }
               if (uriType instanceof AuthnContextDeclRefType)
               {
                  StaxUtil.writeStartElement(writer, ASSERTION_PREFIX,
                        JBossSAMLConstants.AUTHN_CONTEXT_DECLARATION_REF.get(), ASSERTION_NSURI.get());
                  StaxUtil.writeCharacters(writer, uriType.getValue().toASCIIString());
                  StaxUtil.writeEndElement(writer);
               }
            }
         }
      }

      Set<URI> authAuthorities = authContext.getAuthenticatingAuthority();
      if (authAuthorities != null)
      {
         for (URI aa : authAuthorities)
         {
            StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.AUTHENTICATING_AUTHORITY.get(),
                  ASSERTION_NSURI.get());
            StaxUtil.writeCharacters(writer, aa.toASCIIString());
            StaxUtil.writeEndElement(writer);
         }
      }

      StaxUtil.writeEndElement(writer);
      StaxUtil.flush(writer);
   }

   /**
    * write an {@code SubjectType} to stream
    * 
    * @param subject
    * @param out
    * @throws ProcessingException
    */
   public void write(SAML11SubjectType subject) throws ProcessingException
   {
      StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.SUBJECT.get(),
            SAML11Constants.ASSERTION_11_NSURI);

      SAML11SubjectTypeChoice choice = subject.getChoice();
      if (choice != null)
      {
         SAML11NameIdentifierType nameid = choice.getNameID();
         if (nameid != null)
         {
            write(nameid);
         }
      }

      StaxUtil.writeEndElement(writer);
      StaxUtil.flush(writer);
   }

   private void write(BaseIDAbstractType baseId) throws ProcessingException
   {
      throw new RuntimeException("NYI");
   }

   private void write(SubjectConfirmationType subjectConfirmationType) throws ProcessingException
   {
      StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.SUBJECT_CONFIRMATION.get(),
            ASSERTION_NSURI.get());

      StaxUtil.writeAttribute(writer, JBossSAMLConstants.METHOD.get(), subjectConfirmationType.getMethod());

      BaseIDAbstractType baseID = subjectConfirmationType.getBaseID();
      if (baseID != null)
      {
         write(baseID);
      }
      NameIDType nameIDType = subjectConfirmationType.getNameID();
      if (nameIDType != null)
      {
         write(nameIDType, new QName(ASSERTION_NSURI.get(), JBossSAMLConstants.NAMEID.get(), ASSERTION_PREFIX));
      }
      SubjectConfirmationDataType subjectConfirmationData = subjectConfirmationType.getSubjectConfirmationData();
      if (subjectConfirmationData != null)
      {
         write(subjectConfirmationData);
      }
      StaxUtil.writeEndElement(writer);
   }

   private void write(SubjectConfirmationDataType subjectConfirmationData) throws ProcessingException
   {
      StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, JBossSAMLConstants.SUBJECT_CONFIRMATION_DATA.get(),
            ASSERTION_NSURI.get());

      // Let us look at attributes
      String inResponseTo = subjectConfirmationData.getInResponseTo();
      if (StringUtil.isNotNull(inResponseTo))
      {
         StaxUtil.writeAttribute(writer, JBossSAMLConstants.IN_RESPONSE_TO.get(), inResponseTo);
      }

      XMLGregorianCalendar notBefore = subjectConfirmationData.getNotBefore();
      if (notBefore != null)
      {
         StaxUtil.writeAttribute(writer, JBossSAMLConstants.NOT_BEFORE.get(), notBefore.toString());
      }

      XMLGregorianCalendar notOnOrAfter = subjectConfirmationData.getNotOnOrAfter();
      if (notOnOrAfter != null)
      {
         StaxUtil.writeAttribute(writer, JBossSAMLConstants.NOT_ON_OR_AFTER.get(), notOnOrAfter.toString());
      }

      String recipient = subjectConfirmationData.getRecipient();
      if (StringUtil.isNotNull(recipient))
      {
         StaxUtil.writeAttribute(writer, JBossSAMLConstants.RECIPIENT.get(), recipient);
      }

      String address = subjectConfirmationData.getAddress();
      if (StringUtil.isNotNull(address))
      {
         StaxUtil.writeAttribute(writer, JBossSAMLConstants.ADDRESS.get(), address);
      }

      if (subjectConfirmationData instanceof KeyInfoConfirmationDataType)
      {
         KeyInfoConfirmationDataType kicd = (KeyInfoConfirmationDataType) subjectConfirmationData;
         KeyInfoType keyInfo = (KeyInfoType) kicd.getAnyType();
         if (keyInfo.getContent() == null || keyInfo.getContent().size() == 0)
            throw new ProcessingException("Invalid KeyInfo object: content cannot be empty");
         StaxUtil.writeStartElement(this.writer, WSTrustConstants.XMLDSig.DSIG_PREFIX,
               WSTrustConstants.XMLDSig.KEYINFO, WSTrustConstants.XMLDSig.DSIG_NS);
         StaxUtil.writeNameSpace(this.writer, WSTrustConstants.XMLDSig.DSIG_PREFIX, WSTrustConstants.XMLDSig.DSIG_NS);
         // write the keyInfo content.
         Object content = keyInfo.getContent().get(0);
         if (content instanceof Element)
         {
            Element element = (Element) keyInfo.getContent().get(0);
            StaxUtil.writeDOMNode(this.writer, element);
         }
         else if (content instanceof X509DataType)
         {
            X509DataType type = (X509DataType) content;
            if (type.getDataObjects().size() == 0)
               throw new ProcessingException("X509Data cannot be empy");
            StaxUtil.writeStartElement(this.writer, WSTrustConstants.XMLDSig.DSIG_PREFIX,
                  WSTrustConstants.XMLDSig.X509DATA, WSTrustConstants.XMLDSig.DSIG_NS);
            Object obj = type.getDataObjects().get(0);
            if (obj instanceof Element)
            {
               Element element = (Element) obj;
               StaxUtil.writeDOMElement(this.writer, element);
            }
            else if (obj instanceof X509CertificateType)
            {
               X509CertificateType cert = (X509CertificateType) obj;
               StaxUtil.writeStartElement(this.writer, WSTrustConstants.XMLDSig.DSIG_PREFIX,
                     WSTrustConstants.XMLDSig.X509CERT, WSTrustConstants.XMLDSig.DSIG_NS);
               StaxUtil.writeCharacters(this.writer, new String(cert.getEncodedCertificate()));
               StaxUtil.writeEndElement(this.writer);
            }
            StaxUtil.writeEndElement(this.writer);
         }
         StaxUtil.writeEndElement(this.writer);
      }

      StaxUtil.writeEndElement(writer);
      StaxUtil.flush(writer);
   }

   public void write(SAML11NameIdentifierType nameid) throws ProcessingException
   {
      StaxUtil.writeStartElement(writer, ASSERTION_PREFIX, SAML11Constants.NAME_IDENTIFIER,
            SAML11Constants.ASSERTION_11_NSURI);

      URI format = nameid.getFormat();
      if (format != null)
      {
         StaxUtil.writeAttribute(writer, SAML11Constants.FORMAT, format.toString());
      }
      String nameQualifier = nameid.getNameQualifier();
      if (StringUtil.isNotNull(nameQualifier))
      {
         StaxUtil.writeAttribute(writer, SAML11Constants.NAME_QUALIFIER, nameQualifier);
      }

      StaxUtil.writeCharacters(writer, nameid.getValue());

      StaxUtil.writeEndElement(writer);
      StaxUtil.flush(writer);
   }
}