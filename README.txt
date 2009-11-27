README for workspace for Picketlink Federation
==============================================
1) picketlink-xmlsecmodel: Contains the JAXB model for XML Digital Signature and XML Encryption.

2) picketlink-fed-model: JAXB model for spec of SAMLv2 and WS-Trust1.3. Do not put any other JAXB stuff here.

3) picketlink-fed-core: This is the workspace where JBID project developers (not the users) will build the code using the model.

4) picketlink-fed-api: This is the API that the end users should use.

5) picketlink-bindings: This is the server bindings for a non-JBAS environment such as Apache Tomcat. This is where the JAXB model for the IDFed configuration exists.

6) picketlink-bindings-jboss: This is any JBAS specific codebase that builds on the identity bindings.

7) assembly: Builds up the models, core and api consolidated jars. DOES NOT CONTAIN THE BINDINGS (please look at the platform-build project of JBID where zips are built).

==============================================
Eclipse workspaces

The SVN repository for the identity project doesn't contain any IDE-specific files. This means that it is up to the developer to setup the workspace for his/her preferred IDE. Maven has plugins that generate the project files for a number of IDEs, which speeds up the process of setting up a workspace for the project. As an example, this section illustrates how to generate the Eclipse .project and .classpath files:

$ mvn eclipse:eclipse

The command above will cause maven to build the eclipse files based on the dependencies declared in the modules pom.xml file. After generating the .project and .classpath files, all that is needed is to import the projects (each module will result in a separate eclipse project) in the Eclipse IDE.
