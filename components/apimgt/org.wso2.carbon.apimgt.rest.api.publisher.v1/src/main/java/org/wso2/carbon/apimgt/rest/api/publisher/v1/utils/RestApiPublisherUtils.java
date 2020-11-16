/*
 *
 *  Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.wso2.carbon.apimgt.rest.api.publisher.v1.utils;

import graphql.schema.GraphQLSchema;
import graphql.schema.idl.SchemaParser;
import graphql.schema.idl.TypeDefinitionRegistry;
import graphql.schema.idl.UnExecutableSchemaGenerator;
import graphql.schema.validation.SchemaValidationError;
import graphql.schema.validation.SchemaValidator;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.jaxrs.ext.multipart.Attachment;
import org.apache.cxf.jaxrs.ext.multipart.ContentDisposition;
import org.apache.xpath.operations.Bool;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.netbeans.lib.cvsclient.commandLine.command.log;
import org.wso2.carbon.apimgt.api.APIDefinition;
import org.wso2.carbon.apimgt.api.APIDefinitionValidationResponse;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.APIProvider;
import org.wso2.carbon.apimgt.api.model.*;
import org.wso2.carbon.apimgt.api.model.policy.APIPolicy;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.definitions.GraphQLSchemaDefinition;
import org.wso2.carbon.apimgt.impl.definitions.OASParserUtil;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.rest.api.publisher.v1.dto.*;
import org.wso2.carbon.apimgt.rest.api.publisher.v1.utils.mappings.APIMappingUtil;
import org.wso2.carbon.apimgt.rest.api.util.RestApiConstants;
import org.wso2.carbon.apimgt.rest.api.util.utils.RestApiUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.util.*;

public class RestApiPublisherUtils {

    private static final Log log = LogFactory.getLog(RestApiPublisherUtils.class);

    /**
     * Validate endpoint configurations of {@link APIDTO} for web socket endpoints
     *
     * @param api api model
     * @return validity of the web socket api
     */
    public static boolean isValidWSAPI(APIDTO api) {

        boolean isValid = false;

        if (api.getEndpointConfig() != null) {
            LinkedHashMap endpointConfig = (LinkedHashMap) api.getEndpointConfig();
            String prodEndpointUrl = String
                    .valueOf(((LinkedHashMap) endpointConfig.get("production_endpoints")).get("url"));
            String sandboxEndpointUrl = String
                    .valueOf(((LinkedHashMap) endpointConfig.get("sandbox_endpoints")).get("url"));
            isValid = prodEndpointUrl.startsWith("ws://") || prodEndpointUrl.startsWith("wss://");

            if (isValid) {
                isValid = sandboxEndpointUrl.startsWith("ws://") || sandboxEndpointUrl.startsWith("wss://");
            }
        }

        return isValid;
    }

    /**
     * To validate the roles against user roles and tenant roles.
     *
     * @param inputRoles Input roles.
     * @return relevant error string or empty string.
     * @throws APIManagementException API Management Exception.
     */
    public static String validateUserRoles(List<String> inputRoles) throws APIManagementException {

        String userName = RestApiUtil.getLoggedInUsername();
        String[] tenantRoleList = APIUtil.getRoleNames(userName);
        boolean isMatched = false;
        String[] userRoleList = null;

        if (APIUtil.hasPermission(userName, APIConstants.Permissions.APIM_ADMIN)) {
            isMatched = true;
        } else {
            userRoleList = APIUtil.getListOfRoles(userName);
        }
        if (inputRoles != null && !inputRoles.isEmpty()) {
            if (tenantRoleList != null || userRoleList != null) {
                for (String inputRole : inputRoles) {
                    if (!isMatched && userRoleList != null && APIUtil.compareRoleList(userRoleList, inputRole)) {
                        isMatched = true;
                    }
                    if (tenantRoleList != null && !APIUtil.compareRoleList(tenantRoleList, inputRole)) {
                        return "Invalid user roles found in accessControlRole list";
                    }
                }
                return isMatched ? "" : "This user does not have at least one role specified in API access control.";
            } else {
                return "Invalid user roles found";
            }
        }
        return "";
    }

    /**
     * To validate the additional properties.
     * Validation will be done for the keys of additional properties. Property keys should not contain spaces in it
     * and property keys should not conflict with reserved key words.
     *
     * @param additionalProperties Map<String, String>  properties to validate
     * @return error message if there is an validation error with additional properties.
     */
    public static String validateAdditionalProperties(Map<String, String> additionalProperties) {

        if (additionalProperties != null) {
            for (Map.Entry<String, String> entry : additionalProperties.entrySet()) {
                String propertyKey = entry.getKey().trim();
                String propertyValue = entry.getValue();
                if (propertyKey.contains(" ")) {
                    return "Property names should not contain space character. Property '" + propertyKey + "' "
                            + "contains space in it.";
                }
                if (Arrays.asList(APIConstants.API_SEARCH_PREFIXES).contains(propertyKey.toLowerCase())) {
                    return "Property '" + propertyKey + "' conflicts with the reserved keywords. Reserved keywords "
                            + "are [" + Arrays.toString(APIConstants.API_SEARCH_PREFIXES) + "]";
                }
                // Maximum allowable characters of registry property name and value is 100 and 1000. Hence we are
                // restricting them to be within 80 and 900.
                if (propertyKey.length() > 80) {
                    return "Property name can have maximum of 80 characters. Property '" + propertyKey + "' + contains "
                            + propertyKey.length() + "characters";
                }
                if (propertyValue.length() > 900) {
                    return "Property value can have maximum of 900 characters. Property '" + propertyKey + "' + "
                            + "contains a value with " + propertyValue.length() + "characters";
                }
            }
        }
        return "";
    }
    
    /**
     * To validate the roles against and tenant roles.
     *
     * @param inputRoles Input roles.
     * @return relevant error string or empty string.
     * @throws APIManagementException API Management Exception.
     */
    public static String validateRoles(List<String> inputRoles) throws APIManagementException {
        String userName = RestApiUtil.getLoggedInUsername();
        boolean isMatched = false;
        if (inputRoles != null && !inputRoles.isEmpty()) {
            String roleString = String.join(",", inputRoles);
            isMatched = APIUtil.isRoleNameExist(userName, roleString);
            if (!isMatched) {
                return "Invalid user roles found in visibleRoles list";
            }
        }
        return "";
    }

    /**
     * Attaches a file to the specified document
     *
     * @param apiId identifier of the API, the document belongs to
     * @param documentation Documentation object
     * @param inputStream input Stream containing the file
     * @param fileDetails file details object as cxf Attachment
     * @throws APIManagementException if unable to add the file
     */
    public static void attachFileToDocument(String apiId, Documentation documentation, InputStream inputStream,
                                            Attachment fileDetails) throws APIManagementException {

        APIProvider apiProvider = RestApiUtil.getLoggedInUserProvider();
        String tenantDomain = RestApiUtil.getLoggedInUserTenantDomain();
        String documentId = documentation.getId();
        String randomFolderName = RandomStringUtils.randomAlphanumeric(10);
        String tmpFolder = System.getProperty(RestApiConstants.JAVA_IO_TMPDIR) + File.separator
                + RestApiConstants.DOC_UPLOAD_TMPDIR + File.separator + randomFolderName;
        File docFile = new File(tmpFolder);

        boolean folderCreated = docFile.mkdirs();
        if (!folderCreated) {
            RestApiUtil.handleInternalServerError("Failed to add content to the document " + documentId, log);
        }

        InputStream docInputStream = null;
        try {
            ContentDisposition contentDisposition = fileDetails.getContentDisposition();
            String filename = contentDisposition.getParameter(RestApiConstants.CONTENT_DISPOSITION_FILENAME);
            if (StringUtils.isBlank(filename)) {
                filename = RestApiConstants.DOC_NAME_DEFAULT + randomFolderName;
                log.warn(
                        "Couldn't find the name of the uploaded file for the document " + documentId + ". Using name '"
                                + filename + "'");
            }
            APIIdentifier apiIdentifier = APIMappingUtil
                    .getAPIIdentifierFromUUID(apiId, tenantDomain);

            RestApiUtil.transferFile(inputStream, filename, docFile.getAbsolutePath());
            docInputStream = new FileInputStream(docFile.getAbsolutePath() + File.separator + filename);
            String mediaType = fileDetails.getHeader(RestApiConstants.HEADER_CONTENT_TYPE);
            mediaType = mediaType == null ? RestApiConstants.APPLICATION_OCTET_STREAM : mediaType;
            apiProvider.addFileToDocumentation(apiIdentifier, documentation, filename, docInputStream, mediaType);
            apiProvider.updateDocumentation(apiIdentifier, documentation);
            docFile.deleteOnExit();
        } catch (FileNotFoundException e) {
            RestApiUtil.handleInternalServerError("Unable to read the file from path ", e, log);
        } finally {
            IOUtils.closeQuietly(docInputStream);
        }
    }

    /**
     * This method validates monetization properties
     *
     * @param monetizationProperties map of monetization properties
     * @return error message if there is an validation error with monetization properties.
     */
    public static String validateMonetizationProperties(Map<String, String> monetizationProperties) {

        if (monetizationProperties != null) {
            for (Map.Entry<String, String> entry : monetizationProperties.entrySet()) {
                String monetizationPropertyKey = entry.getKey().trim();
                String propertyValue = entry.getValue();
                if (monetizationPropertyKey.contains(" ")) {
                    return "Monetization property names should not contain space character. " +
                            "Monetization property '" + monetizationPropertyKey + "' "
                            + "contains space in it.";
                }
                // Maximum allowable characters of registry property name and value is 100 and 1000.
                // Hence we are restricting them to be within 80 and 900.
                if (monetizationPropertyKey.length() > 80) {
                    return "Monetization property name can have maximum of 80 characters. " +
                            "Monetization property '" + monetizationPropertyKey + "' + contains "
                            + monetizationPropertyKey.length() + "characters";
                }
                if (propertyValue.length() > 900) {
                    return "Monetization property value can have maximum of 900 characters. " +
                            "Property '" + monetizationPropertyKey + "' + "
                            + "contains a value with " + propertyValue.length() + "characters";
                }
            }
        }
        return "";
    }

    /**
     * Attaches a file to the specified product document
     *
     * @param productId identifier of the API Product, the document belongs to
     * @param documentation Documentation object
     * @param inputStream input Stream containing the file
     * @param fileDetails file details object as cxf Attachment
     * @throws APIManagementException if unable to add the file
     */
    public static void attachFileToProductDocument(String productId, Documentation documentation, InputStream inputStream,
            Attachment fileDetails) throws APIManagementException {

        APIProvider apiProvider = RestApiUtil.getLoggedInUserProvider();
        String tenantDomain = RestApiUtil.getLoggedInUserTenantDomain();
        String documentId = documentation.getId();
        String randomFolderName = RandomStringUtils.randomAlphanumeric(10);
        String tmpFolder = System.getProperty(RestApiConstants.JAVA_IO_TMPDIR) + File.separator
                + RestApiConstants.DOC_UPLOAD_TMPDIR + File.separator + randomFolderName;
        File docFile = new File(tmpFolder);

        boolean folderCreated = docFile.mkdirs();
        if (!folderCreated) {
            RestApiUtil.handleInternalServerError("Failed to add content to the document " + documentId, log);
        }

        InputStream docInputStream = null;
        try {
            ContentDisposition contentDisposition = fileDetails.getContentDisposition();
            String filename = contentDisposition.getParameter(RestApiConstants.CONTENT_DISPOSITION_FILENAME);
            if (StringUtils.isBlank(filename)) {
                filename = RestApiConstants.DOC_NAME_DEFAULT + randomFolderName;
                log.warn(
                        "Couldn't find the name of the uploaded file for the document " + documentId + ". Using name '"
                                + filename + "'");
            }
            APIProductIdentifier productIdentifier = APIMappingUtil
                    .getAPIProductIdentifierFromUUID(productId, tenantDomain);

            RestApiUtil.transferFile(inputStream, filename, docFile.getAbsolutePath());
            docInputStream = new FileInputStream(docFile.getAbsolutePath() + File.separator + filename);
            String mediaType = fileDetails.getHeader(RestApiConstants.HEADER_CONTENT_TYPE);
            mediaType = mediaType == null ? RestApiConstants.APPLICATION_OCTET_STREAM : mediaType;
            apiProvider.addFileToProductDocumentation(productIdentifier, documentation, filename, docInputStream, mediaType);
            apiProvider.updateDocumentation(productIdentifier, documentation);
            docFile.deleteOnExit();
        } catch (FileNotFoundException e) {
            RestApiUtil.handleInternalServerError("Unable to read the file from path ", e, log);
        } finally {
            IOUtils.closeQuietly(docInputStream);
        }
    }

    /**
     * This method will validate the given xml content for the syntactical correctness
     *
     * @param xmlContent string of xml content
     * @return true if the xml content is valid, false otherwise
     * @throws APIManagementException
     */
    public static boolean validateXMLSchema(String xmlContent) throws APIManagementException {
        xmlContent = "<xml>" + xmlContent + "</xml>";
        DocumentBuilderFactory factory = APIUtil.getSecuredDocumentBuilder();
        factory.setValidating(false);
        factory.setNamespaceAware(false);
        try {
            DocumentBuilder builder = factory.newDocumentBuilder();
            builder.parse(new InputSource(new StringReader(xmlContent)));
        } catch (ParserConfigurationException | IOException | SAXException e) {
            log.error("Error occurred while parsing the provided xml content.", e);
            return false;
        }
        return true;
    }

    /**
     * This method is to get the default SOAP API Resource definition. (SOAPAction, SOAP Request)
     * @return String
     * */
    public static String getSOAPOperation() {
        return "{\"/*\":{\"post\":{\"parameters\":[{\"schema\":{\"type\":\"string\"},\"description\":\"SOAP request.\","
            + "\"name\":\"SOAP Request\",\"required\":true,\"in\":\"body\"},"
                + "{\"description\":\"SOAPAction header for soap 1.1\",\"name\":\"SOAPAction\",\"type\":\"string\","
                + "\"required\":false,\"in\":\"header\"}],\"responses\":{\"200\":{\"description\":\"OK\"}}," +
                "\"security\":[{\"default\":[]}],\"consumes\":[\"text/xml\",\"application/soap+xml\"]}}}";
    }

    /**
     * Prepares the API Model object to be created using the DTO object
     *
     * @param body APIDTO of the API
     * @return API object to be created
     * @throws APIManagementException Error while creating the API
     */
    public static API prepareToCreateAPIByDTO(APIDTO body) throws APIManagementException {
        APIProvider apiProvider = RestApiUtil.getLoggedInUserProvider();
        String username = RestApiUtil.getLoggedInUsername();
        List<String> apiSecuritySchemes = body.getSecurityScheme();//todo check list vs string
        if (!apiProvider.isClientCertificateBasedAuthenticationConfigured() && apiSecuritySchemes != null) {
            for (String apiSecurityScheme : apiSecuritySchemes) {
                if (apiSecurityScheme.contains(APIConstants.API_SECURITY_MUTUAL_SSL)) {
                    RestApiUtil.handleBadRequest("Mutual SSL Based authentication is not supported in this server", log);
                }
            }
        }
        if (body.getAccessControlRoles() != null) {
            String errorMessage = RestApiPublisherUtils.validateUserRoles(body.getAccessControlRoles());

            if (!errorMessage.isEmpty()) {
                RestApiUtil.handleBadRequest(errorMessage, log);
            }
        }
        if (body.getAdditionalProperties() != null) {
            String errorMessage = RestApiPublisherUtils
                    .validateAdditionalProperties(body.getAdditionalProperties());
            if (!errorMessage.isEmpty()) {
                RestApiUtil.handleBadRequest(errorMessage, log);
            }
        }
        if (body.getContext() == null) {
            RestApiUtil.handleBadRequest("Parameter: \"context\" cannot be null", log);
        } else if (body.getContext().endsWith("/")) {
            RestApiUtil.handleBadRequest("Context cannot end with '/' character", log);
        }
        if (apiProvider.isApiNameWithDifferentCaseExist(body.getName())) {
            RestApiUtil.handleBadRequest("Error occurred while adding API. API with name " + body.getName()
                    + " already exists.", log);
        }
        if (body.getAuthorizationHeader() == null) {
            body.setAuthorizationHeader(APIUtil
                    .getOAuthConfigurationFromAPIMConfig(APIConstants.AUTHORIZATION_HEADER));
        }
        if (body.getAuthorizationHeader() == null) {
            body.setAuthorizationHeader(APIConstants.AUTHORIZATION_HEADER_DEFAULT);
        }

        if (body.getVisibility() == APIDTO.VisibilityEnum.RESTRICTED && body.getVisibleRoles().isEmpty()) {
            RestApiUtil.handleBadRequest("Valid roles should be added under 'visibleRoles' to restrict " +
                    "the visibility", log);
        }
        if (body.getVisibleRoles() != null) {
            String errorMessage = RestApiPublisherUtils.validateRoles(body.getVisibleRoles());
            if (!errorMessage.isEmpty()) {
                RestApiUtil.handleBadRequest(errorMessage, log);
            }
        }

        //Get all existing versions of  api been adding
        List<String> apiVersions = apiProvider.getApiVersionsMatchingApiName(body.getName(), username);
        if (apiVersions.size() > 0) {
            //If any previous version exists
            for (String version : apiVersions) {
                if (version.equalsIgnoreCase(body.getVersion())) {
                    //If version already exists
                    if (apiProvider.isDuplicateContextTemplate(body.getContext())) {
                        RestApiUtil.handleResourceAlreadyExistsError("Error occurred while " +
                                "adding the API. A duplicate API already exists for "
                                + body.getName() + "-" + body.getVersion(), log);
                    } else {
                        RestApiUtil.handleBadRequest("Error occurred while adding API. API with name " +
                                body.getName() + " already exists with different " +
                                "context", log);
                    }
                }
            }
        } else {
            //If no any previous version exists
            if (apiProvider.isDuplicateContextTemplate(body.getContext())) {
                RestApiUtil.handleBadRequest("Error occurred while adding the API. A duplicate API context " +
                        "already exists for " + body.getContext(), log);
            }
        }

        //Check if the user has admin permission before applying a different provider than the current user
        String provider = body.getProvider();
        if (!StringUtils.isBlank(provider) && !provider.equals(username)) {
            Boolean isUserHasDevopsRole = null;
            try {
                isUserHasDevopsRole = APIUtil.checkIfUserInRole(username, APIConstants.DEVOPS_ROLE);
            } catch (UserStoreException e) {
                RestApiUtil.handleInternalServerError(e.getMessage(), e, log);
            }
            if (!APIUtil.hasPermission(username, APIConstants.Permissions.APIM_ADMIN) || !isUserHasDevopsRole) {
                if (log.isDebugEnabled()) {
                    if (!isUserHasDevopsRole) {
                        RestApiUtil.handleBadRequest("User " + username + " does not have "
                                + APIConstants.DEVOPS_ROLE + " role.", log);
                    }
                    log.debug("User " + username + " does not have admin permission ("
                            + APIConstants.Permissions.APIM_ADMIN + ") hence provider (" +
                            provider + ") overridden with current user (" + username + ")");
                }
                provider = username;
            } else {
                if (!APIUtil.isUserExist(provider)) {
                    RestApiUtil.handleBadRequest("Specified provider " + provider + " not exist.", log);
                }
            }
        } else {
            //Set username in case provider is null or empty
            provider = username;
        }

        List<String> tiersFromDTO = body.getPolicies();

        //check whether the added API's tiers are all valid
        Set<Tier> definedTiers = apiProvider.getTiers();
        List<String> invalidTiers = RestApiUtil.getInvalidTierNames(definedTiers, tiersFromDTO);
        if (invalidTiers.size() > 0) {
            RestApiUtil.handleBadRequest(
                    "Specified tier(s) " + Arrays.toString(invalidTiers.toArray()) + " are invalid", log);
        }
        APIPolicy apiPolicy = apiProvider.getAPIPolicy(username, body.getApiThrottlingPolicy());
        if (apiPolicy == null && body.getApiThrottlingPolicy() != null) {
            RestApiUtil.handleBadRequest(
                    "Specified policy " + body.getApiThrottlingPolicy() + " is invalid", log);
        }

        API apiToAdd = APIMappingUtil.fromDTOtoAPI(body, provider);
        //Overriding some properties:
        //only allow CREATED as the stating state for the new api if not status is PROTOTYPED
        if (!APIConstants.PROTOTYPED.equals(apiToAdd.getStatus())) {
            apiToAdd.setStatus(APIConstants.CREATED);
        }
        //we are setting the api owner as the logged in user until we support checking admin privileges and assigning
        //  the owner as a different user
        apiToAdd.setApiOwner(provider);

        //attach micro-geteway labels
        assignLabelsToDTO(body, apiToAdd);
        if (body.getKeyManagers() instanceof List) {
            apiToAdd.setKeyManagers((List<String>) body.getKeyManagers());
        } else if (body.getKeyManagers() == null) {
            apiToAdd.setKeyManagers(
                    Collections.singletonList(APIConstants.KeyManager.API_LEVEL_ALL_KEY_MANAGERS));
        } else {
            throw new APIManagementException("KeyManagers value need to be an array");
        }
        return apiToAdd;
    }

    /**
     * This method is used to assign micro gateway labels to the DTO
     *
     * @param apiDTO API DTO
     * @param api    the API object
     * @return the API object with labels
     */
    public static API assignLabelsToDTO(APIDTO apiDTO, API api) {

        if (apiDTO.getLabels() != null) {
            List<String> labels = apiDTO.getLabels();
            List<Label> labelList = new ArrayList<>();
            for (String label : labels) {
                Label mgLabel = new Label();
                mgLabel.setName(label);
                labelList.add(mgLabel);
            }
            api.setGatewayLabels(labelList);
        }
        return api;
    }

    /**
     * This method is used to sync operations in APIDTO and swagger, and add the swagger file and the API
     *
     * @param apiDTOFromProperties API DTO
     * @param validationResponse   Response of the validated swagger defnition
     * @param apiToAdd             the API object
     * @param apiProvider          API Provider
     * @return the added API object
     */
    public static API syncOperationsAndAddSwaggerWithAPI(APIDTO apiDTOFromProperties,
                                                   APIDefinitionValidationResponse validationResponse, API apiToAdd,
                                                   APIProvider apiProvider) throws APIManagementException {
        boolean syncOperations = apiDTOFromProperties.getOperations().size() > 0;
        // Rearrange paths according to the API payload and save the OpenAPI definition

        APIDefinition apiDefinition = validationResponse.getParser();
        SwaggerData swaggerData;
        String definitionToAdd = validationResponse.getJsonContent();
        if (syncOperations) {
            validateScopes(apiToAdd);
            swaggerData = new SwaggerData(apiToAdd);
            definitionToAdd = apiDefinition.populateCustomManagementInfo(definitionToAdd, swaggerData);
        }
        definitionToAdd = OASParserUtil.preProcess(definitionToAdd);
        Set<URITemplate> uriTemplates = apiDefinition.getURITemplates(definitionToAdd);
        Set<Scope> scopes = apiDefinition.getScopes(definitionToAdd);
        apiToAdd.setUriTemplates(uriTemplates);
        apiToAdd.setScopes(scopes);
        //Set extensions from API definition to API object
        apiToAdd = OASParserUtil.setExtensionsToAPI(definitionToAdd, apiToAdd);
        if (!syncOperations) {
            validateScopes(apiToAdd);
            swaggerData = new SwaggerData(apiToAdd);
            definitionToAdd = apiDefinition
                    .populateCustomManagementInfo(validationResponse.getJsonContent(), swaggerData);
        }

        // adding the API and definition
        apiProvider.addAPI(apiToAdd);
        apiProvider.saveSwaggerDefinition(apiToAdd, definitionToAdd);

        // retrieving the added API for returning as the response
        API addedAPI = apiProvider.getAPI(apiToAdd.getId());
        return  addedAPI;
    }

    /**
     * validate user inout scopes
     *
     * @param api api information
     * @throws APIManagementException throw if validation failure
     */
    public static void validateScopes(API api) throws APIManagementException {

        APIIdentifier apiId = api.getId();
        String username = RestApiUtil.getLoggedInUsername();
        String tenantDomain = RestApiUtil.getLoggedInUserTenantDomain();
        int tenantId = APIUtil.getTenantIdFromTenantDomain(tenantDomain);
        APIProvider apiProvider = RestApiUtil.getProvider(username);
        Set<Scope> sharedAPIScopes = new HashSet<>();

        for (Scope scope : api.getScopes()) {
            String scopeName = scope.getKey();
            if (!(APIUtil.isAllowedScope(scopeName))) {
                // Check if each scope key is already assigned as a local scope to a different API which is also not a
                // different version of the same API. If true, return error.
                // If false, check if the scope key is already defined as a shared scope. If so, do not honor the
                // other scope attributes (description, role bindings) in the request payload, replace them with
                // already defined values for the existing shared scope.
                if (apiProvider.isScopeKeyAssignedLocally(apiId, scopeName, tenantId)) {
                    RestApiUtil
                            .handleBadRequest("Scope " + scopeName + " is already assigned locally by another "
                                    + "API", log);
                } else if (apiProvider.isSharedScopeNameExists(scopeName, tenantDomain)) {
                    sharedAPIScopes.add(scope);
                    continue;
                }
            }

            //set display name as empty if it is not provided
            if (StringUtils.isBlank(scope.getName())) {
                scope.setName(scopeName);
            }

            //set description as empty if it is not provided
            if (StringUtils.isBlank(scope.getDescription())) {
                scope.setDescription("");
            }
            if (scope.getRoles() != null) {
                for (String aRole : scope.getRoles().split(",")) {
                    boolean isValidRole = APIUtil.isRoleNameExist(username, aRole);
                    if (!isValidRole) {
                        String error = "Role '" + aRole + "' does not exist.";
                        RestApiUtil.handleBadRequest(error, log);
                    }
                }
            }
        }

        apiProvider.validateSharedScopes(sharedAPIScopes, tenantDomain);
    }

    /**
     * Validate GraphQL Schema
     *
     * @param filename file name of the schema
     * @param schema GraphQL schema
     */
    public static GraphQLValidationResponseDTO isValidGraphQLSchema(String filename, String schema) {
        String errorMessage;
        GraphQLValidationResponseDTO validationResponse = new GraphQLValidationResponseDTO();
        if (filename.endsWith(".graphql") || filename.endsWith(".txt") || filename.endsWith(".sdl")) {
            if (schema.isEmpty()) {
                errorMessage = "GraphQL Schema cannot be empty or null to validate it";
                RestApiUtil.handleBadRequest(errorMessage, log);
            }
            SchemaParser schemaParser = new SchemaParser();
            TypeDefinitionRegistry typeRegistry = schemaParser.parse(schema);
            GraphQLSchema graphQLSchema = UnExecutableSchemaGenerator.makeUnExecutableSchema(typeRegistry);
            SchemaValidator schemaValidation = new SchemaValidator();
            Set<SchemaValidationError> validationErrors = schemaValidation.validateSchema(graphQLSchema);

            if (validationErrors.toArray().length > 0) {
                errorMessage = "InValid Schema";
                validationResponse.isValid(Boolean.FALSE);
                validationResponse.errorMessage(errorMessage);
            } else {
                validationResponse.setIsValid(Boolean.TRUE);
                GraphQLValidationResponseGraphQLInfoDTO graphQLInfo = new GraphQLValidationResponseGraphQLInfoDTO();
                GraphQLSchemaDefinition graphql = new GraphQLSchemaDefinition();
                List<URITemplate> operationList = graphql.extractGraphQLOperationList(schema, null);
                List<APIOperationsDTO> operationArray = APIMappingUtil.fromURITemplateListToOprationList(operationList);
                graphQLInfo.setOperations(operationArray);
                GraphQLSchemaDTO schemaObj = new GraphQLSchemaDTO();
                schemaObj.setSchemaDefinition(schema);
                graphQLInfo.setGraphQLSchema(schemaObj);
                validationResponse.setGraphQLInfo(graphQLInfo);
            }
        }
        else {
            RestApiUtil.handleBadRequest("Unsupported extension type of file: " + filename, log);
        }
        return validationResponse;
    }

    public static void validateDocumentTypeAndSourceURL(DocumentDTO documentDTO) {
        if (documentDTO.getType() == DocumentDTO.TypeEnum.OTHER &&
                org.apache.commons.lang3.StringUtils.isBlank(documentDTO.getOtherTypeName())) {
            //check otherTypeName for not null if doc type is OTHER
            RestApiUtil.handleBadRequest("otherTypeName cannot be empty if type is OTHER.", log);
        }
        String sourceUrl = documentDTO.getSourceUrl();
        if (documentDTO.getSourceType() == DocumentDTO.SourceTypeEnum.URL &&
                (org.apache.commons.lang3.StringUtils.isBlank(sourceUrl) || !RestApiUtil.isURL(sourceUrl))) {
            RestApiUtil.handleBadRequest("Invalid document sourceUrl Format", log);
        }
    }
}
