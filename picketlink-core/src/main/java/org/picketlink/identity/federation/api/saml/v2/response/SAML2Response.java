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
package org.picketlink.identity.federation.api.saml.v2.response;

import static org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLConstants.LOGOUT_RESPONSE;
import static org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants.PROTOCOL_NSURI;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Writer;
import java.net.URI;
import java.util.Arrays;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.log4j.Logger;
import org.picketlink.identity.federation.core.ErrorCodes;
import org.picketlink.identity.federation.core.exceptions.ConfigurationException;
import org.picketlink.identity.federation.core.exceptions.ParsingException;
import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.parsers.saml.SAMLParser;
import org.picketlink.identity.federation.core.saml.v2.common.SAMLDocumentHolder;
import org.picketlink.identity.federation.core.saml.v2.common.SAMLProtocolContext;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.core.saml.v2.exceptions.IssueInstantMissingException;
import org.picketlink.identity.federation.core.saml.v2.factories.JBossSAMLAuthnResponseFactory;
import org.picketlink.identity.federation.core.saml.v2.holders.IDPInfoHolder;
import org.picketlink.identity.federation.core.saml.v2.holders.IssuerInfoHolder;
import org.picketlink.identity.federation.core.saml.v2.holders.SPInfoHolder;
import org.picketlink.identity.federation.core.saml.v2.util.AssertionUtil;
import org.picketlink.identity.federation.core.saml.v2.util.DocumentUtil;
import org.picketlink.identity.federation.core.saml.v2.util.XMLTimeUtil;
import org.picketlink.identity.federation.core.saml.v2.writers.SAMLResponseWriter;
import org.picketlink.identity.federation.core.sts.PicketLinkCoreSTS;
import org.picketlink.identity.federation.core.util.JAXPValidationUtil;
import org.picketlink.identity.federation.core.util.StaxUtil;
import org.picketlink.identity.federation.saml.v2.SAML2Object;
import org.picketlink.identity.federation.saml.v2.assertion.ActionType;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.AuthnContextClassRefType;
import org.picketlink.identity.federation.saml.v2.assertion.AuthnContextType;
import org.picketlink.identity.federation.saml.v2.assertion.AuthnContextType.AuthnContextTypeSequence;
import org.picketlink.identity.federation.saml.v2.assertion.AuthnStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.AuthzDecisionStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.DecisionType;
import org.picketlink.identity.federation.saml.v2.assertion.EncryptedAssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.EncryptedElementType;
import org.picketlink.identity.federation.saml.v2.assertion.EvidenceType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectConfirmationDataType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectConfirmationType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusResponseType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * API for dealing with SAML2 Response objects
 *
 * @author Anil.Saldhana@redhat.com
 * @since Jan 5, 2009
 */
public class SAML2Response {
    private static Logger log = Logger.getLogger(SAML2Response.class);

    private final boolean trace = log.isTraceEnabled();

    private SAMLDocumentHolder samlDocumentHolder = null;

    /**
     * Create an assertion
     *
     * @param id
     * @param issuer
     * @return
     */
    public AssertionType createAssertion(String id, NameIDType issuer) {
        return AssertionUtil.createAssertion(id, issuer);
    }

    /**
     * Create an AuthnStatement
     *
     * @param authnContextDeclRef such as JBossSAMLURIConstants.AC_PASSWORD_PROTECTED_TRANSPORT
     * @param issueInstant
     * @return
     */
    public AuthnStatementType createAuthnStatement(String authnContextDeclRef, XMLGregorianCalendar issueInstant) {
        AuthnStatementType authnStatement = new AuthnStatementType(issueInstant);
        AuthnContextType act = new AuthnContextType();
        String authContextDeclRef = JBossSAMLURIConstants.AC_PASSWORD_PROTECTED_TRANSPORT.get();
        act.addAuthenticatingAuthority(URI.create(authContextDeclRef));

        AuthnContextTypeSequence sequence = act.new AuthnContextTypeSequence();
        sequence.setClassRef(new AuthnContextClassRefType(URI.create(JBossSAMLURIConstants.AC_PASSWORD.get())));
        act.setSequence(sequence);

        authnStatement.setAuthnContext(act);
        return authnStatement;
    }

    /**
     * Create an Authorization Decision Statement Type
     *
     * @param resource
     * @param decision
     * @param evidence
     * @param actions
     * @return
     */
    public AuthzDecisionStatementType createAuthzDecisionStatementType(String resource, DecisionType decision,
            EvidenceType evidence, ActionType... actions) {
        AuthzDecisionStatementType authzDecST = new AuthzDecisionStatementType();
        authzDecST.setResource(resource);
        authzDecST.setDecision(decision);
        if (evidence != null)
            authzDecST.setEvidence(evidence);

        if (actions != null) {
            authzDecST.getAction().addAll(Arrays.asList(actions));
        }

        return authzDecST;
    }

    /**
     * Construct a {@link ResponseType} without calling PicketLink STS for the assertion. The {@link AssertionType} is generated
     * within this method
     *
     * @param ID id of the {@link ResponseType}
     * @param sp
     * @param idp
     * @param issuerInfo
     * @return
     * @throws ConfigurationException
     * @throws ProcessingException
     */
    public ResponseType createResponseType(String ID, SPInfoHolder sp, IDPInfoHolder idp, IssuerInfoHolder issuerInfo,
            AssertionType assertion) throws ConfigurationException, ProcessingException {
        String responseDestinationURI = sp.getResponseDestinationURI();

        XMLGregorianCalendar issueInstant = XMLTimeUtil.getIssueInstant();

        // Create assertion -> subject
        SubjectType subjectType = new SubjectType();

        // subject -> nameid
        NameIDType nameIDType = new NameIDType();
        nameIDType.setFormat(URI.create(idp.getNameIDFormat()));
        nameIDType.setValue(idp.getNameIDFormatValue());

        SubjectType.STSubType subType = new SubjectType.STSubType();
        subType.addBaseID(nameIDType);
        subjectType.setSubType(subType);

        SubjectConfirmationType subjectConfirmation = new SubjectConfirmationType();
        subjectConfirmation.setMethod(idp.getSubjectConfirmationMethod());

        SubjectConfirmationDataType subjectConfirmationData = new SubjectConfirmationDataType();
        subjectConfirmationData.setInResponseTo(sp.getRequestID());
        subjectConfirmationData.setRecipient(responseDestinationURI);
        subjectConfirmationData.setNotBefore(issueInstant);
        subjectConfirmationData.setNotOnOrAfter(issueInstant);

        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

        subjectType.addConfirmation(subjectConfirmation);

        // Update the subjectConfirmationData expiry based on the assertion
        if (assertion.getConditions() != null) {
            subjectConfirmationData.setNotOnOrAfter(assertion.getConditions().getNotOnOrAfter());
        }

        ResponseType responseType = createResponseType(ID, issuerInfo, assertion);
        // InResponseTo ID
        responseType.setInResponseTo(sp.getRequestID());
        // Destination
        responseType.setDestination(responseDestinationURI);

        return responseType;
    }

    /**
     * Create a ResponseType
     *
     * <b>NOTE:</b>: The PicketLink STS is used to issue/update the assertion
     *
     * If you want to control over the assertion being issued, then use
     * {@link #createResponseType(String, SPInfoHolder, IDPInfoHolder, IssuerInfoHolder, AssertionType)}
     *
     * @param ID id of the response
     * @param sp holder with the information about the Service Provider
     * @param idp holder with the information on the Identity Provider
     * @param issuerInfo holder with information on the issuer
     * @return
     * @throws ConfigurationException
     * @throws ProcessingException
     */
    public ResponseType createResponseType(String ID, SPInfoHolder sp, IDPInfoHolder idp, IssuerInfoHolder issuerInfo)
            throws ConfigurationException, ProcessingException {
        String responseDestinationURI = sp.getResponseDestinationURI();

        XMLGregorianCalendar issueInstant = XMLTimeUtil.getIssueInstant();

        // Create assertion -> subject
        SubjectType subjectType = new SubjectType();

        // subject -> nameid
        NameIDType nameIDType = new NameIDType();
        nameIDType.setFormat(URI.create(idp.getNameIDFormat()));
        nameIDType.setValue(idp.getNameIDFormatValue());

        SubjectType.STSubType subType = new SubjectType.STSubType();
        subType.addBaseID(nameIDType);
        subjectType.setSubType(subType);

        SubjectConfirmationType subjectConfirmation = new SubjectConfirmationType();
        subjectConfirmation.setMethod(idp.getSubjectConfirmationMethod());

        SubjectConfirmationDataType subjectConfirmationData = new SubjectConfirmationDataType();
        subjectConfirmationData.setInResponseTo(sp.getRequestID());
        subjectConfirmationData.setRecipient(responseDestinationURI);
        subjectConfirmationData.setNotBefore(issueInstant);
        subjectConfirmationData.setNotOnOrAfter(issueInstant);

        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

        subjectType.addConfirmation(subjectConfirmation);

        PicketLinkCoreSTS sts = PicketLinkCoreSTS.instance();
        SAMLProtocolContext samlProtocolContext = new SAMLProtocolContext();
        samlProtocolContext.setSubjectType(subjectType);
        samlProtocolContext.setIssuerID(issuerInfo.getIssuer());

        AssertionType assertionType = idp.getAssertion();
        if (assertionType != null) {
            samlProtocolContext.setIssuedAssertion(assertionType);
            // renew it
            sts.renewToken(samlProtocolContext);
        } else
            sts.issueToken(samlProtocolContext);

        assertionType = samlProtocolContext.getIssuedAssertion();

        // Update the subjectConfirmationData expiry based on the assertion
        if (assertionType.getConditions() != null) {
            subjectConfirmationData.setNotOnOrAfter(assertionType.getConditions().getNotOnOrAfter());
        }

        ResponseType responseType = createResponseType(ID, issuerInfo, assertionType);
        // InResponseTo ID
        responseType.setInResponseTo(sp.getRequestID());
        // Destination
        responseType.setDestination(responseDestinationURI);

        return responseType;
    }

    /**
     * Create an empty response type
     *
     * @return
     */
    public ResponseType createResponseType(String ID) {
        try {
            return new ResponseType(ID, XMLTimeUtil.getIssueInstant());
        } catch (ConfigurationException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Create a ResponseType
     *
     * @param ID
     * @param issuerInfo
     * @param assertion
     * @return
     * @throws ConfigurationException
     */
    public ResponseType createResponseType(String ID, IssuerInfoHolder issuerInfo, AssertionType assertion)
            throws ConfigurationException {
        return JBossSAMLAuthnResponseFactory.createResponseType(ID, issuerInfo, assertion);
    }

    /**
     * Create a ResponseType
     *
     * @param ID
     * @param issuerInfo
     * @param encryptedAssertion a DOM {@link Element} that represents an encrypted assertion
     * @return
     * @throws ConfigurationException
     */
    public ResponseType createResponseType(String ID, IssuerInfoHolder issuerInfo, Element encryptedAssertion)
            throws ConfigurationException {
        return JBossSAMLAuthnResponseFactory.createResponseType(ID, issuerInfo, encryptedAssertion);
    }

    /**
     * Add validity conditions to the SAML2 Assertion
     *
     * @param assertion
     * @param durationInMilis
     * @throws ConfigurationException
     * @throws IssueInstantMissingException
     */
    public void createTimedConditions(AssertionType assertion, long durationInMilis) throws ConfigurationException,
            IssueInstantMissingException {
        AssertionUtil.createTimedConditions(assertion, durationInMilis);
    }

    /**
     * Get an encrypted assertion from the stream
     *
     * @param is
     * @return
     * @throws ParsingException
     * @throws ProcessingException
     * @throws ConfigurationException
     */
    public EncryptedAssertionType getEncryptedAssertion(InputStream is) throws ParsingException, ConfigurationException,
            ProcessingException {
        if (is == null)
            throw new IllegalArgumentException(ErrorCodes.NULL_ARGUMENT + "inputstream");

        Document samlDocument = DocumentUtil.getDocument(is);
        SAMLParser samlParser = new SAMLParser();
        JAXPValidationUtil.checkSchemaValidation(samlDocument);

        return (EncryptedAssertionType) samlParser.parse(DocumentUtil.getNodeAsStream(samlDocument));

    }

    /**
     * Read an assertion from an input stream
     *
     * @param is
     * @return
     * @throws ParsingException
     * @throws ProcessingException
     * @throws ConfigurationException
     */
    public AssertionType getAssertionType(InputStream is) throws ParsingException, ConfigurationException, ProcessingException {
        if (is == null)
            throw new IllegalArgumentException(ErrorCodes.NULL_ARGUMENT + "inputstream");
        Document samlDocument = DocumentUtil.getDocument(is);

        SAMLParser samlParser = new SAMLParser();
        JAXPValidationUtil.checkSchemaValidation(samlDocument);
        return (AssertionType) samlParser.parse(DocumentUtil.getNodeAsStream(samlDocument));
    }

    /**
     * Get the parsed {@code SAMLDocumentHolder}
     *
     * @return
     */
    public SAMLDocumentHolder getSamlDocumentHolder() {
        return samlDocumentHolder;
    }

    /**
     * Read a ResponseType from an input stream
     *
     * @param is
     * @return
     * @throws ParsingException
     * @throws ConfigurationException
     */
    public ResponseType getResponseType(InputStream is) throws ParsingException, ConfigurationException, ProcessingException {
        if (is == null)
            throw new IllegalArgumentException(ErrorCodes.NULL_ARGUMENT + "inputstream");

        Document samlResponseDocument = DocumentUtil.getDocument(is);

        SAMLParser samlParser = new SAMLParser();
        JAXPValidationUtil.checkSchemaValidation(samlResponseDocument);

        ResponseType responseType = (ResponseType) samlParser.parse(DocumentUtil.getNodeAsStream(samlResponseDocument));

        samlDocumentHolder = new SAMLDocumentHolder(responseType, samlResponseDocument);
        return responseType;
    }

    /**
     * Read a {@code SAML2Object} from an input stream
     *
     * @param is
     * @return
     * @throws ParsingException
     * @throws ConfigurationException
     * @throws ProcessingException
     */
    public SAML2Object getSAML2ObjectFromStream(InputStream is) throws ParsingException, ConfigurationException,
            ProcessingException {
        if (is == null)
            throw new IllegalArgumentException(ErrorCodes.NULL_ARGUMENT + "inputstream");

        Document samlResponseDocument = DocumentUtil.getDocument(is);

        if (trace)
            log.trace("RESPONSE=" + DocumentUtil.asString(samlResponseDocument));

        SAMLParser samlParser = new SAMLParser();
        JAXPValidationUtil.checkSchemaValidation(samlResponseDocument);

        InputStream responseStream = DocumentUtil.getNodeAsStream(samlResponseDocument);
        SAML2Object responseType = (SAML2Object) samlParser.parse(responseStream);

        samlDocumentHolder = new SAMLDocumentHolder(responseType, samlResponseDocument);
        return responseType;

    }

    /**
     * Convert an EncryptedElement into a Document
     *
     * @param encryptedElementType
     * @return
     * @throws ConfigurationException
     */
    public Document convert(EncryptedElementType encryptedElementType) throws ConfigurationException {
        if (encryptedElementType == null)
            throw new IllegalArgumentException(ErrorCodes.NULL_ARGUMENT + "encryptedElementType");
        Document doc = DocumentUtil.createDocument();
        Node importedNode = doc.importNode(encryptedElementType.getEncryptedElement(), true);
        doc.appendChild(importedNode);

        return doc;
    }

    /**
     * Convert a SAML2 Response into a Document
     *
     * @param responseType
     * @return
     * @throws ParsingException
     * @throws ConfigurationException
     * @throws ParserConfigurationException
     */
    public Document convert(StatusResponseType responseType) throws ProcessingException, ConfigurationException,
            ParsingException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        SAMLResponseWriter writer = new SAMLResponseWriter(StaxUtil.getXMLStreamWriter(bos));

        if (responseType instanceof ResponseType) {
            ResponseType response = (ResponseType) responseType;
            writer.write(response);
        } else {
            writer.write(responseType, new QName(PROTOCOL_NSURI.get(), LOGOUT_RESPONSE.get(), "samlp"));
        }

        return DocumentUtil.getDocument(new ByteArrayInputStream(bos.toByteArray()));
    }

    /**
     * Marshall the response type to the output stream
     *
     * @param responseType
     * @param os
     * @throws ProcessingException
     */
    public void marshall(ResponseType responseType, OutputStream os) throws ProcessingException {
        SAMLResponseWriter samlWriter = new SAMLResponseWriter(StaxUtil.getXMLStreamWriter(os));
        samlWriter.write(responseType);
    }

    /**
     * Marshall the ResponseType into a writer
     *
     * @param responseType
     * @param writer
     * @throws ProcessingException
     */
    public void marshall(ResponseType responseType, Writer writer) throws ProcessingException {
        SAMLResponseWriter samlWriter = new SAMLResponseWriter(StaxUtil.getXMLStreamWriter(writer));
        samlWriter.write(responseType);
    }
}