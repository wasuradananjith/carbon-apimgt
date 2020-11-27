/*
 *  Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.apimgt.rest.api.publisher.v1.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.parser.ParseException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.wso2.carbon.apimgt.api.APIDefinitionValidationResponse;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.APIMgtAuthorizationFailedException;
import org.wso2.carbon.apimgt.api.APIMgtResourceNotFoundException;
import org.wso2.carbon.apimgt.api.APIProvider;
import org.wso2.carbon.apimgt.api.FaultGatewaysException;
import org.wso2.carbon.apimgt.api.WorkflowStatus;
import org.wso2.carbon.apimgt.api.dto.ClientCertificateDTO;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.APIIdentifier;
import org.wso2.carbon.apimgt.api.model.APIStateChangeResponse;
import org.wso2.carbon.apimgt.api.model.APIStatus;
import org.wso2.carbon.apimgt.api.model.ApiTypeWrapper;
import org.wso2.carbon.apimgt.api.model.Documentation;
import org.wso2.carbon.apimgt.api.model.Identifier;
import org.wso2.carbon.apimgt.api.model.ResourceFile;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.certificatemgt.ResponseCode;
import org.wso2.carbon.apimgt.impl.definitions.OASParserUtil;
import org.wso2.carbon.apimgt.impl.importexport.APIImportExportConstants;
import org.wso2.carbon.apimgt.impl.importexport.APIImportExportException;
import org.wso2.carbon.apimgt.impl.importexport.ImportExportConstants;
import org.wso2.carbon.apimgt.impl.importexport.lifecycle.LifeCycle;
import org.wso2.carbon.apimgt.impl.importexport.lifecycle.LifeCycleTransition;
import org.wso2.carbon.apimgt.impl.importexport.utils.CommonUtil;
import org.wso2.carbon.apimgt.impl.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.impl.utils.APIMWSDLReader;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.impl.wsdl.model.WSDLValidationResponse;
import org.wso2.carbon.apimgt.impl.wsdl.util.SOAPToRESTConstants;
import org.wso2.carbon.apimgt.rest.api.publisher.v1.dto.APIDTO;
import org.wso2.carbon.apimgt.rest.api.publisher.v1.dto.DocumentDTO;
import org.wso2.carbon.apimgt.rest.api.publisher.v1.dto.GraphQLValidationResponseDTO;
import org.wso2.carbon.apimgt.rest.api.publisher.v1.impl.ApisApiServiceImpl;
import org.wso2.carbon.apimgt.rest.api.util.utils.RestApiUtil;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.api.RegistryException;
import org.wso2.carbon.registry.api.Resource;
import org.wso2.carbon.registry.core.RegistryConstants;
import org.wso2.carbon.registry.core.session.UserRegistry;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;

public class ImportUtils {

    private static final Log log = LogFactory.getLog(ImportUtils.class);
    private static final String IN = "in";
    private static final String OUT = "out";
    private static final String SOAPTOREST = "SoapToRest";

    /**
     * This method imports an API.
     *
     * @param extractedFolderPath Location of the extracted folder of the API
     * @param preserveProvider    Decision to keep or replace the provider
     * @param overwrite           Whether to update the API or not
     * @throws APIImportExportException If there is an error in importing an API
     */
    public static void importApi(String extractedFolderPath, Boolean preserveProvider, Boolean overwrite)
            throws APIImportExportException {
        String userName = RestApiUtil.getLoggedInUsername();
        APIDefinitionValidationResponse swaggerDefinitionValidationResponse = null;
        String graphQLSchema = null;
        API importedApi = null;
        String currentStatus;
        String targetStatus;
        String lifecycleAction;
        int tenantId = 0;

        try {
            APIProvider apiProvider = RestApiUtil.getLoggedInUserProvider();
            JsonElement jsonObject = retrieveValidatedDTOObject(extractedFolderPath, preserveProvider, userName);

            APIDTO importedApiDTO = new Gson().fromJson(jsonObject, APIDTO.class);
            String apiType = importedApiDTO.getType().toString();

            // Validate swagger content except for WebSocket APIs
            if (!APIConstants.APITransportType.WS.toString().equalsIgnoreCase(apiType)) {
                swaggerDefinitionValidationResponse = retrieveValidatedSwaggerDefinitionFromArchive(
                        extractedFolderPath);
            }
            // Validate the GraphQL schema
            if (APIConstants.APITransportType.GRAPHQL.toString().equalsIgnoreCase(apiType)) {
                graphQLSchema = retrieveValidatedGraphqlSchemaFromArchive(extractedFolderPath);
            }
            // Validate the WSDL of SOAP/SOAPTOREST APIs
            if (APIConstants.API_TYPE_SOAP.equalsIgnoreCase(apiType) || APIConstants.API_TYPE_SOAPTOREST
                    .equalsIgnoreCase(apiType)) {
                validateWSDLFromArchive(extractedFolderPath, importedApiDTO);
            }

            String currentTenantDomain = MultitenantUtils.getTenantDomain(APIUtil.replaceEmailDomainBack(userName));
            ApisApiServiceImpl apisApiService = new ApisApiServiceImpl();

            // The status of the importing API should be stored separately to do the lifecycle change at the end
            targetStatus = importedApiDTO.getLifeCycleStatus();

            // If the overwrite is set to true (which means an update), retrieve the existing API
            if (Boolean.TRUE.equals(overwrite)) {
                API targetApi = retrieveApiToOverwrite(importedApiDTO, currentTenantDomain, apiProvider);
                currentStatus = targetApi.getStatus();
                // Set the status of imported API to current status of target API when updating
                importedApiDTO.setLifeCycleStatus(currentStatus);
                importedApi = RestApiPublisherUtils.updateApi(targetApi, importedApiDTO, apiProvider);
            } else {
                // Initialize to CREATED when import
                currentStatus = APIStatus.CREATED.toString();
                importedApiDTO.setLifeCycleStatus(currentStatus);
                importedApi = apisApiService.addAPIWithGeneratedSwaggerDefinition(importedApiDTO, apiProvider,
                        ImportExportConstants.OAS_VERSION_3);
            }

            // Retrieving the life cycle action to do the lifecycle state change explicitly later
            lifecycleAction = getLifeCycleAction(currentTenantDomain, currentStatus, targetStatus, apiProvider);

            // Add/update swagger content except for WebSocket APIs
            if (!APIConstants.APITransportType.WS.toString().equalsIgnoreCase(apiType)) {
                // Add the validated swagger separately since the UI does the same procedure
                apisApiService.updateSwagger(importedApi.getUUID(), swaggerDefinitionValidationResponse);
            }
            // Add the GraphQL schema
            if (APIConstants.APITransportType.GRAPHQL.toString().equalsIgnoreCase(apiType)) {
                apisApiService.addGraphQLSchema(importedApi, graphQLSchema, apiProvider);
            }

            tenantId = APIUtil.getTenantId(RestApiUtil.getLoggedInUsername());
            UserRegistry registry = ServiceReferenceHolder.getInstance().getRegistryService()
                    .getGovernanceSystemRegistry(tenantId);

            // Since Image, documents, sequences and WSDL are optional, exceptions are logged and ignored in implementation
            ApiTypeWrapper apiTypeWrapperWithUpdatedApi = new ApiTypeWrapper(importedApi);
            addThumbnailImage(extractedFolderPath, apiTypeWrapperWithUpdatedApi, apiProvider);
            addDocumentation(extractedFolderPath, apiTypeWrapperWithUpdatedApi, apiProvider);
            addAPISequences(extractedFolderPath, importedApi, registry);
            addAPISpecificSequences(extractedFolderPath, importedApi, registry);
            addAPIWsdl(extractedFolderPath, importedApi, apiProvider, registry);
            addEndpointCertificates(extractedFolderPath, importedApi, apiProvider, tenantId);
            addSOAPToREST(extractedFolderPath, importedApi, registry);

            if (apiProvider.isClientCertificateBasedAuthenticationConfigured()) {
                if (log.isDebugEnabled()) {
                    log.debug("Mutual SSL enabled. Importing client certificates.");
                }
                addClientCertificates(extractedFolderPath, apiProvider);
            }

            // Change API lifecycle if state transition is required
            if (StringUtils.isNotEmpty(lifecycleAction)) {
                log.info("Changing lifecycle from " + currentStatus + " to " + targetStatus);
                if (StringUtils.equals(lifecycleAction, APIConstants.LC_PUBLISH_LC_STATE)) {
                    apiProvider.changeAPILCCheckListItems(importedApi.getId(),
                            APIImportExportConstants.REFER_REQUIRE_RE_SUBSCRIPTION_CHECK_ITEM, true);
                }
                apiProvider.changeLifeCycleStatus(importedApi.getId(), lifecycleAction);
            }
        } catch (CryptoException e) {
            String errorMessage = "Error while reading API meta information from path: " + extractedFolderPath;
            throw new APIImportExportException(errorMessage, e);
        } catch (IOException e) {
            String errorMessage = "Error while reading API meta information from path: " + extractedFolderPath;
            throw new APIImportExportException(errorMessage, e);
        } catch (FaultGatewaysException e) {
            String errorMessage = "Error while updating API: " + importedApi.getId().getApiName();
            throw new APIImportExportException(errorMessage, e);
        } catch (RegistryException e) {
            String errorMessage = "Error while getting governance registry for tenant: " + tenantId;
            throw new APIImportExportException(errorMessage, e);
        } catch (APIManagementException e) {
            String errorMessage = "Error while importing API: ";
            if (importedApi != null) {
                errorMessage +=
                        importedApi.getId().getApiName() + StringUtils.SPACE + APIConstants.API_DATA_VERSION + ": "
                                + importedApi.getId().getVersion();
            }
            throw new APIImportExportException(errorMessage + StringUtils.SPACE + e.getMessage(), e);
        } catch (ParseException e) {
            String errorMessage = "Error while parsing the endpoint configuration of the API";
            throw new APIImportExportException(errorMessage, e);
        }
    }

    /**
     * This method retrieves an API to overwrite in the current tenant domain.
     *
     * @param apiDto              API DTO
     * @param currentTenantDomain Current tenant domain
     * @param apiProvider         API Provider
     * @throws APIManagementException If an error occurs when retrieving the API to overwrite
     */
    private static API retrieveApiToOverwrite(APIDTO apiDto, String currentTenantDomain, APIProvider apiProvider)
            throws APIManagementException {
        String apiName = apiDto.getName();
        String apiVersion = apiDto.getVersion();
        String provider = APIUtil.getAPIProviderFromAPINameVersionTenant(apiName, apiVersion, currentTenantDomain);
        APIIdentifier apiIdentifier = new APIIdentifier(APIUtil.replaceEmailDomain(provider), apiName, apiVersion);

        // Checking whether the API exists
        if (!apiProvider.isAPIAvailable(apiIdentifier)) {
            String errorMessage =
                    "Error occurred while updating. API: " + apiName + StringUtils.SPACE + APIConstants.API_DATA_VERSION
                            + ": " + apiVersion + " not found";
            throw new APIMgtResourceNotFoundException(errorMessage);
        }
        return apiProvider.getAPI(apiIdentifier);
    }

    /**
     * Extract the imported archive to a temporary folder and return the folder path of it
     *
     * @param uploadedInputStream Input stream from the REST request
     * @return Path to the extracted directory
     * @throws APIImportExportException If an error occurs while creating the directory, transferring files or
     *                                  extracting the content
     */
    public static String getArchivePathOfExtractedDirectory(InputStream uploadedInputStream)
            throws APIImportExportException {
        //Temporary directory is used to create the required folders
        File importFolder = CommonUtil.createTempDirectory(null);
        String uploadFileName = ImportExportConstants.UPLOAD_FILE_NAME;
        String absolutePath = importFolder.getAbsolutePath() + File.separator;
        CommonUtil.transferFile(uploadedInputStream, uploadFileName, absolutePath);
        String extractedFolderName = CommonUtil.extractArchive(new File(absolutePath + uploadFileName), absolutePath);
        return absolutePath + extractedFolderName;
    }

    /**
     * Validate API/API Product configuration (api.yaml/api.json)  and return it.
     *
     * @param pathToArchive            Path to the extracted folder
     * @param isDefaultProviderAllowed Preserve provider flag value
     * @param currentUser              Username of the current user
     * @throws APIMgtAuthorizationFailedException If an error occurs while authorizing the provider
     */
    private static JsonElement retrieveValidatedDTOObject(String pathToArchive, Boolean isDefaultProviderAllowed,
            String currentUser) throws IOException, APIMgtAuthorizationFailedException {
        // Get API Definition as JSON
        String jsonContent = getAPIDefinitionAsJson(pathToArchive);
        if (jsonContent == null) {
            throw new IOException("Cannot find API definition. api.json or api.yaml should present");
        }
        // Retrieving the field "data" in api.yaml/json and convert it to a JSON object for further processing
        JsonElement configElement = new JsonParser().parse(jsonContent).getAsJsonObject().get(APIConstants.DATA);
        JsonObject configObject = configElement.getAsJsonObject();

        // Locate the "provider" within the "id" and set it as the current user
        String apiName = configObject.get(ImportExportConstants.API_NAME_ELEMENT).getAsString();
        String apiVersion = configObject.get(ImportExportConstants.VERSION_ELEMENT).getAsString();

        // Remove spaces of API Name/version if present
        if (apiName != null && apiVersion != null) {
            configObject.remove(apiName);
            configObject.addProperty(ImportExportConstants.API_NAME_ELEMENT, apiName.replace(" ", ""));
            configObject.remove(apiVersion);
            configObject.addProperty(ImportExportConstants.VERSION_ELEMENT, apiVersion.replace(" ", ""));
        } else {
            throw new IOException("API Name (id.name) and Version (id.version) must be provided in api.yaml");
        }

        configObject = validatePreserveProvider(configObject, isDefaultProviderAllowed, currentUser);
        return configObject;
    }

    /**
     * Validate the provider of the API and modify the provider based on the preserveProvider flag value.
     *
     * @param configObject             Data object from the API/API Product configuration
     * @param isDefaultProviderAllowed Preserve provider flag value
     * @throws APIMgtAuthorizationFailedException If an error occurs while authorizing the provider
     */
    private static JsonObject validatePreserveProvider(JsonObject configObject, Boolean isDefaultProviderAllowed,
            String currentUser) throws APIMgtAuthorizationFailedException {
        String prevProvider = configObject.get(ImportExportConstants.PROVIDER_ELEMENT).getAsString();
        String prevTenantDomain = MultitenantUtils.getTenantDomain(APIUtil.replaceEmailDomainBack(prevProvider));
        String currentTenantDomain = MultitenantUtils.getTenantDomain(APIUtil.replaceEmailDomainBack(currentUser));

        if (isDefaultProviderAllowed) {
            if (!StringUtils.equals(prevTenantDomain, currentTenantDomain)) {
                String errorMessage =
                        "Tenant mismatch! Please enable preserveProvider property " + "for cross tenant API Import.";
                throw new APIMgtAuthorizationFailedException(errorMessage);
            }
        } else {
            String prevProviderWithDomain = APIUtil.replaceEmailDomain(prevProvider);
            String currentUserWithDomain = APIUtil.replaceEmailDomain(currentUser);
            configObject.remove(ImportExportConstants.PROVIDER_ELEMENT);
            configObject.addProperty(ImportExportConstants.PROVIDER_ELEMENT, currentUserWithDomain);

            if (configObject.get(ImportExportConstants.WSDL_URL) != null) {
                // If original provider is not preserved, replace provider name in the wsdl URL
                // with the current user with domain name
                configObject.addProperty(ImportExportConstants.WSDL_URL,
                        configObject.get(ImportExportConstants.WSDL_URL).getAsString()
                                .replace(prevProviderWithDomain, currentUserWithDomain));
            }
            configObject = setCurrentProviderToContext(configObject, currentTenantDomain, prevTenantDomain);
        }
        return configObject;
    }

    /**
     * Replace original provider name from imported API/API Product context with the logged in username
     * This method is used when "preserveProvider" property is set to false.
     *
     * @param jsonObject     Imported API or API Product
     * @param currentDomain  Current domain name
     * @param previousDomain Original domain name
     */
    public static JsonObject setCurrentProviderToContext(JsonObject jsonObject, String currentDomain,
            String previousDomain) {
        String context = jsonObject.get(APIConstants.API_DOMAIN_MAPPINGS_CONTEXT).getAsString();
        if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equalsIgnoreCase(currentDomain)
                && !MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equalsIgnoreCase(previousDomain)) {
            jsonObject.remove(APIConstants.API_DOMAIN_MAPPINGS_CONTEXT);
            jsonObject.addProperty(APIConstants.API_DOMAIN_MAPPINGS_CONTEXT,
                    context.replace(APIConstants.TENANT_PREFIX + previousDomain, StringUtils.EMPTY));
        } else if (!MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equalsIgnoreCase(currentDomain)
                && MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equalsIgnoreCase(previousDomain)) {
            jsonObject.remove(APIConstants.API_DOMAIN_MAPPINGS_CONTEXT);
            jsonObject.addProperty(APIConstants.API_DOMAIN_MAPPINGS_CONTEXT,
                    APIConstants.TENANT_PREFIX + currentDomain + context);
        } else if (!StringUtils.equalsIgnoreCase(currentDomain, previousDomain)) {
            jsonObject.remove(APIConstants.API_DOMAIN_MAPPINGS_CONTEXT);
            jsonObject.addProperty(APIConstants.API_DOMAIN_MAPPINGS_CONTEXT,
                    context.replace(previousDomain, currentDomain));
        }
        return jsonObject;
    }

    /**
     * Retrieve API Definition as JSON.
     *
     * @param pathToArchive Path to API or API Product archive
     * @throws IOException If an error occurs while reading the file
     */
    public static String getAPIDefinitionAsJson(String pathToArchive) throws IOException {
        String jsonContent = null;
        String pathToYamlFile = pathToArchive + ImportExportConstants.YAML_API_FILE_LOCATION;
        String pathToJsonFile = pathToArchive + ImportExportConstants.JSON_API_FILE_LOCATION;

        // Load yaml representation first if it is present
        if (CommonUtil.checkFileExistence(pathToYamlFile)) {
            if (log.isDebugEnabled()) {
                log.debug("Found api definition file " + pathToYamlFile);
            }
            String yamlContent = FileUtils.readFileToString(new File(pathToYamlFile));
            jsonContent = CommonUtil.yamlToJson(yamlContent);
        } else if (CommonUtil.checkFileExistence(pathToJsonFile)) {
            // load as a json fallback
            if (log.isDebugEnabled()) {
                log.debug("Found api definition file " + pathToJsonFile);
            }
            jsonContent = FileUtils.readFileToString(new File(pathToJsonFile));
        }
        return jsonContent;
    }

    /**
     * Validate GraphQL Schema definition from the archive directory and return it.
     *
     * @param pathToArchive Path to API archive
     * @throws IOException If an error occurs while reading the file
     */
    private static String retrieveValidatedGraphqlSchemaFromArchive(String pathToArchive)
            throws IOException, APIImportExportException {
        File file = new File(pathToArchive + ImportExportConstants.GRAPHQL_SCHEMA_DEFINITION_LOCATION);
        String schemaDefinition = loadGraphqlSDLFile(pathToArchive);
        GraphQLValidationResponseDTO graphQLValidationResponseDTO = RestApiPublisherUtils
                .validateGraphQLSchema(file.getName(), schemaDefinition);
        if (!graphQLValidationResponseDTO.isIsValid()) {
            String errMsg = "Error occurred while importing the API. Invalid GraphQL schema definition found. "
                    + graphQLValidationResponseDTO.getErrorMessage();
            throw new APIImportExportException(errMsg);
        }
        return schemaDefinition;
    }

    /**
     * Validate WSDL definition from the archive directory and return it.
     *
     * @param pathToArchive Path to API archive
     * @throws APIImportExportException If an error due to an invalid WSDL definition
     * @throws IOException              If an error occurs while reading the file
     * @throws APIManagementException   If an error occurs while retrieving the WSDL processor
     */
    private static void validateWSDLFromArchive(String pathToArchive, APIDTO apiDto)
            throws APIImportExportException, IOException, APIManagementException {
        byte[] wsdlDefinition = loadWsdlFile(pathToArchive, apiDto);
        WSDLValidationResponse wsdlValidationResponse = APIMWSDLReader.
                getWsdlValidationResponse(APIMWSDLReader.getWSDLProcessor(wsdlDefinition));
        if (!wsdlValidationResponse.isValid()) {
            String errMsg =
                    "Error occurred while importing the API. Invalid WSDL definition found. " + wsdlValidationResponse
                            .getError();
            throw new APIImportExportException(errMsg);
        }
    }

    /**
     * Load the graphQL schema definition from archive.
     *
     * @param pathToArchive Path to archive
     * @return Schema definition content
     * @throws IOException When SDL file not found
     */
    private static String loadGraphqlSDLFile(String pathToArchive) throws IOException {
        if (CommonUtil.checkFileExistence(pathToArchive + ImportExportConstants.GRAPHQL_SCHEMA_DEFINITION_LOCATION)) {
            if (log.isDebugEnabled()) {
                log.debug("Found graphQL sdl file " + pathToArchive
                        + ImportExportConstants.GRAPHQL_SCHEMA_DEFINITION_LOCATION);
            }
            return FileUtils.readFileToString(
                    new File(pathToArchive, ImportExportConstants.GRAPHQL_SCHEMA_DEFINITION_LOCATION));
        }
        throw new IOException("Missing graphQL schema definition file. schema.graphql should be present.");
    }

    /**
     * Load the WSDL definition from archive.
     *
     * @param pathToArchive Path to archive
     * @param apiDto        API DTO to add
     * @return Schema definition content
     * @throws IOException When WSDL file not found
     */
    private static byte[] loadWsdlFile(String pathToArchive, APIDTO apiDto) throws IOException {
        String wsdlFileName = apiDto.getName() + "-" + apiDto.getVersion() + APIConstants.WSDL_FILE_EXTENSION;
        String pathToFile = pathToArchive + ImportExportConstants.WSDL_LOCATION + wsdlFileName;
        if (CommonUtil.checkFileExistence(pathToFile)) {
            if (log.isDebugEnabled()) {
                log.debug("Found WSDL file " + pathToFile);
            }
            return FileUtils.readFileToByteArray(new File(pathToFile));
        }
        throw new IOException("Missing WSDL file. It should be present.");
    }

    /**
     * Validate swagger definition from the archive directory and return it.
     *
     * @param pathToArchive Path to API or API Product archive
     * @throws IOException If an error occurs while reading the file
     */
    private static APIDefinitionValidationResponse retrieveValidatedSwaggerDefinitionFromArchive(String pathToArchive)
            throws APIManagementException, APIImportExportException, IOException {
        String swaggerContent = loadSwaggerFile(pathToArchive);
        APIDefinitionValidationResponse validationResponse = OASParserUtil
                .validateAPIDefinition(swaggerContent, Boolean.TRUE);
        if (!validationResponse.isValid()) {
            String errMsg =
                    "Error occurred while importing the API. Invalid Swagger definition found. " + validationResponse
                            .getErrorItems();
            throw new APIImportExportException(errMsg);
        }
        return validationResponse;
    }

    /**
     * Load a swagger document from archive. This method lookup for swagger as YAML or JSON.
     *
     * @param pathToArchive Path to archive
     * @return Swagger content as a JSON
     * @throws IOException When swagger document not found
     */
    public static String loadSwaggerFile(String pathToArchive) throws IOException {
        if (CommonUtil.checkFileExistence(pathToArchive + ImportExportConstants.YAML_SWAGGER_DEFINITION_LOCATION)) {
            if (log.isDebugEnabled()) {
                log.debug(
                        "Found swagger file " + pathToArchive + ImportExportConstants.YAML_SWAGGER_DEFINITION_LOCATION);
            }
            String yamlContent = FileUtils
                    .readFileToString(new File(pathToArchive + ImportExportConstants.YAML_SWAGGER_DEFINITION_LOCATION));
            return CommonUtil.yamlToJson(yamlContent);
        } else if (CommonUtil
                .checkFileExistence(pathToArchive + ImportExportConstants.JSON_SWAGGER_DEFINITION_LOCATION)) {
            if (log.isDebugEnabled()) {
                log.debug(
                        "Found swagger file " + pathToArchive + ImportExportConstants.JSON_SWAGGER_DEFINITION_LOCATION);
            }
            return FileUtils
                    .readFileToString(new File(pathToArchive + ImportExportConstants.JSON_SWAGGER_DEFINITION_LOCATION));
        }
        throw new IOException("Missing swagger file. Either swagger.json or swagger.yaml should present");
    }

    /**
     * This method update the API or API Product with the icon to be displayed at the API store.
     *
     * @param pathToArchive  Location of the extracted folder of the API or API Product
     * @param apiTypeWrapper The imported API object
     */
    private static void addThumbnailImage(String pathToArchive, ApiTypeWrapper apiTypeWrapper,
            APIProvider apiProvider) {

        //Adding image icon to the API if there is any
        File imageFolder = new File(pathToArchive + ImportExportConstants.IMAGE_FILE_LOCATION);
        File[] fileArray = imageFolder.listFiles();
        if (imageFolder.isDirectory() && fileArray != null) {
            //This loop locates the icon of the API
            for (File imageFile : fileArray) {
                if (imageFile != null && imageFile.getName().contains(APIConstants.API_ICON_IMAGE)) {
                    updateWithThumbnail(imageFile, apiTypeWrapper, apiProvider);
                    //the loop is terminated after successfully locating the icon
                    break;
                }
            }
        }
    }

    /**
     * This method update the API Product with the thumbnail image from imported API Product.
     *
     * @param imageFile      Image file
     * @param apiTypeWrapper API or API Product to update
     * @param apiProvider    API Provider
     */
    private static void updateWithThumbnail(File imageFile, ApiTypeWrapper apiTypeWrapper, APIProvider apiProvider) {

        Identifier identifier = apiTypeWrapper.getId();
        String fileName = imageFile.getName();
        String mimeType = URLConnection.guessContentTypeFromName(fileName);
        if (StringUtils.isBlank(mimeType)) {
            try {
                // Check whether the icon is in .json format (UI icons are stored as .json)
                new JsonParser().parse(new FileReader(imageFile));
                mimeType = APIConstants.APPLICATION_JSON_MEDIA_TYPE;
            } catch (JsonParseException e) {
                // Here the exceptions were handled and logged that may arise when parsing the .json file,
                // and this will not break the flow of importing the API.
                // If the .json is wrong or cannot be found the API import process will still be carried out.
                log.error("Failed to read the thumbnail file. ", e);
            } catch (FileNotFoundException e) {
                log.error("Failed to find the thumbnail file. ", e);
            }
        }
        try (FileInputStream inputStream = new FileInputStream(imageFile.getAbsolutePath())) {
            ResourceFile apiImage = new ResourceFile(inputStream, mimeType);
            String thumbPath = APIUtil.getIconPath(identifier);
            String thumbnailUrl = apiProvider.addResourceFile(identifier, thumbPath, apiImage);
            apiTypeWrapper.setThumbnailUrl(APIUtil.prependTenantPrefix(thumbnailUrl, identifier.getProviderName()));
            APIUtil.setResourcePermissions(identifier.getProviderName(), null, null, thumbPath);
            if (apiTypeWrapper.isAPIProduct()) {
                apiProvider.updateAPIProduct(apiTypeWrapper.getApiProduct());
            } else {
                apiProvider.updateAPI(apiTypeWrapper.getApi());
            }
        } catch (FaultGatewaysException e) {
            //This is logged and process is continued because icon is optional for an API
            log.error("Failed to update API/API Product after adding icon. ", e);
        } catch (APIManagementException e) {
            log.error("Failed to add icon to the API/API Product: " + identifier.getName(), e);
        } catch (FileNotFoundException e) {
            log.error("Icon for API/API Product: " + identifier.getName() + " is not found.", e);
        } catch (IOException e) {
            log.error("Failed to import icon for API/API Product:" + identifier.getName());
        }
    }

    /**
     * This method adds the documents to the imported API or API Product.
     *
     * @param pathToArchive  Location of the extracted folder of the API or API Product
     * @param apiTypeWrapper Imported API or API Product
     */
    private static void addDocumentation(String pathToArchive, ApiTypeWrapper apiTypeWrapper, APIProvider apiProvider) {

        String jsonContent = null;
        Identifier identifier = apiTypeWrapper.getId();
        String docDirectoryPath = pathToArchive + File.separator + ImportExportConstants.DOCUMENT_DIRECTORY;

        File documentsFolder = new File(docDirectoryPath);
        File[] fileArray = documentsFolder.listFiles();

        try {
            // Remove all documents associated with the API before update
            List<Documentation> documents = apiProvider.getAllDocumentation(identifier);
            if (documents != null) {
                for (Documentation documentation : documents) {
                    apiProvider.removeDocumentation(identifier, documentation.getId());
                }
            }

            if (documentsFolder.isDirectory() && fileArray != null) {
                //This loop locates the documents inside each repo
                for (File documentFile : fileArray) {
                    String folderName = documentFile.getName();
                    String individualDocumentFilePath = docDirectoryPath + File.separator + folderName;
                    String pathToYamlFile = individualDocumentFilePath + ImportExportConstants.DOCUMENT_FILE_NAME
                            + ImportExportConstants.YAML_EXTENSION;
                    String pathToJsonFile = individualDocumentFilePath + ImportExportConstants.DOCUMENT_FILE_NAME
                            + ImportExportConstants.JSON_EXTENSION;

                    // Load document file if exists
                    if (CommonUtil.checkFileExistence(pathToYamlFile)) {
                        if (log.isDebugEnabled()) {
                            log.debug("Found documents definition file " + pathToYamlFile);
                        }
                        String yamlContent = FileUtils.readFileToString(new File(pathToYamlFile));
                        jsonContent = CommonUtil.yamlToJson(yamlContent);
                    } else if (CommonUtil.checkFileExistence(pathToJsonFile)) {
                        //load as a json fallback
                        if (log.isDebugEnabled()) {
                            log.debug("Found documents definition file " + pathToJsonFile);
                        }
                        jsonContent = FileUtils.readFileToString(new File(pathToJsonFile));
                    }

                    JsonElement configElement = new JsonParser().parse(jsonContent).getAsJsonObject()
                            .get(APIConstants.DATA);
                    DocumentDTO documentDTO = new Gson().fromJson(configElement.getAsJsonObject(), DocumentDTO.class);

                    // Add the documentation DTO
                    Documentation documentation = apiTypeWrapper.isAPIProduct() ?
                            RestApiPublisherUtils
                                    .addDocumentationToAPI(documentDTO, apiTypeWrapper.getApiProduct().getUuid()) :
                            RestApiPublisherUtils.addDocumentationToAPI(documentDTO, apiTypeWrapper.getApi().getUUID());

                    // Adding doc content
                    String docSourceType = documentation.getSourceType().toString();
                    boolean docContentExists =
                            Documentation.DocumentSourceType.INLINE.toString().equalsIgnoreCase(docSourceType)
                                    || Documentation.DocumentSourceType.MARKDOWN.toString()
                                    .equalsIgnoreCase(docSourceType);
                    if (docContentExists) {
                        try (FileInputStream inputStream = new FileInputStream(
                                individualDocumentFilePath + File.separator + folderName)) {
                            String inlineContent = IOUtils.toString(inputStream, ImportExportConstants.CHARSET);
                            if (!apiTypeWrapper.isAPIProduct()) {
                                apiProvider.addDocumentationContent(apiTypeWrapper.getApi(), documentation.getName(),
                                        inlineContent);
                            } else {
                                apiProvider.addProductDocumentationContent(apiTypeWrapper.getApiProduct(),
                                        documentation.getName(), inlineContent);
                            }
                        }
                    } else if (ImportExportConstants.FILE_DOC_TYPE.equalsIgnoreCase(docSourceType)) {
                        String filePath = documentation.getFilePath();
                        try (FileInputStream inputStream = new FileInputStream(
                                individualDocumentFilePath + File.separator + filePath)) {
                            String docExtension = FilenameUtils.getExtension(
                                    pathToArchive + File.separator + ImportExportConstants.DOCUMENT_DIRECTORY
                                            + File.separator + filePath);
                            ResourceFile apiDocument = new ResourceFile(inputStream, docExtension);
                            String visibleRolesList = apiTypeWrapper.getVisibleRoles();
                            String[] visibleRoles = new String[0];
                            if (visibleRolesList != null) {
                                visibleRoles = visibleRolesList.split(",");
                            }
                            String filePathDoc = APIUtil.getDocumentationFilePath(identifier, filePath);
                            APIUtil.setResourcePermissions(apiTypeWrapper.getId().getProviderName(),
                                    apiTypeWrapper.getVisibility(), visibleRoles, filePathDoc);
                            documentation.setFilePath(
                                    apiProvider.addResourceFile(apiTypeWrapper.getId(), filePathDoc, apiDocument));
                            if (!apiTypeWrapper.isAPIProduct()) {
                                apiProvider.updateDocumentation(apiTypeWrapper.getApi().getId(), documentation);
                            } else {
                                apiProvider.updateDocumentation(apiTypeWrapper.getApiProduct().getId(), documentation);
                            }
                        } catch (FileNotFoundException e) {
                            //this error is logged and ignored because documents are optional in an API
                            log.error("Failed to locate the document files of the API/API Product: " + apiTypeWrapper
                                    .getId().getName(), e);
                            continue;
                        }
                    }

                }
            }
        } catch (FileNotFoundException e) {
            //this error is logged and ignored because documents are optional in an API
            log.error("Failed to locate the document files of the API/API Product: " + identifier.getName(), e);
        } catch (APIManagementException | IOException e) {
            //this error is logged and ignored because documents are optional in an API
            log.error("Failed to add Documentations to API/API Product: " + identifier.getName(), e);
        }
    }

    /**
     * This method adds API sequences to the imported API. If the sequence is a newly defined one, it is added.
     *
     * @param pathToArchive Location of the extracted folder of the API
     * @param importedApi   The imported API object
     * @param registry      Registry
     */
    private static void addAPISequences(String pathToArchive, API importedApi, Registry registry) {

        String inSequenceFileName = importedApi.getInSequence() + APIConstants.XML_EXTENSION;
        String inSequenceFileLocation = pathToArchive + ImportExportConstants.IN_SEQUENCE_LOCATION + inSequenceFileName;
        String regResourcePath;

        //Adding in-sequence, if any
        if (CommonUtil.checkFileExistence(inSequenceFileLocation)) {
            regResourcePath = APIConstants.API_CUSTOM_INSEQUENCE_LOCATION + inSequenceFileName;
            addSequenceToRegistry(false, registry, inSequenceFileLocation, regResourcePath);
        }

        String outSequenceFileName = importedApi.getOutSequence() + APIConstants.XML_EXTENSION;
        String outSequenceFileLocation =
                pathToArchive + ImportExportConstants.OUT_SEQUENCE_LOCATION + outSequenceFileName;

        //Adding out-sequence, if any
        if (CommonUtil.checkFileExistence(outSequenceFileLocation)) {
            regResourcePath = APIConstants.API_CUSTOM_OUTSEQUENCE_LOCATION + outSequenceFileName;
            addSequenceToRegistry(false, registry, outSequenceFileLocation, regResourcePath);
        }

        String faultSequenceFileName = importedApi.getFaultSequence() + APIConstants.XML_EXTENSION;
        String faultSequenceFileLocation =
                pathToArchive + ImportExportConstants.FAULT_SEQUENCE_LOCATION + faultSequenceFileName;

        //Adding fault-sequence, if any
        if (CommonUtil.checkFileExistence(faultSequenceFileLocation)) {
            regResourcePath = APIConstants.API_CUSTOM_FAULTSEQUENCE_LOCATION + faultSequenceFileName;
            addSequenceToRegistry(false, registry, faultSequenceFileLocation, regResourcePath);
        }
    }

    /**
     * This method adds API Specific sequences added through the Publisher to the imported API. If the specific
     * sequence already exists, it is updated.
     *
     * @param pathToArchive Location of the extracted folder of the API
     * @param importedApi   The imported API object
     * @param registry      Registry
     */
    private static void addAPISpecificSequences(String pathToArchive, API importedApi, Registry registry) {

        String regResourcePath = APIConstants.API_ROOT_LOCATION + RegistryConstants.PATH_SEPARATOR + importedApi.getId()
                .getProviderName() + RegistryConstants.PATH_SEPARATOR + importedApi.getId().getApiName()
                + RegistryConstants.PATH_SEPARATOR + importedApi.getId().getVersion()
                + RegistryConstants.PATH_SEPARATOR;

        // Add custom in-sequence
        addCustomSequenceToRegistry(pathToArchive, registry, regResourcePath, importedApi.getInSequence(),
                ImportExportConstants.IN_SEQUENCE_LOCATION, APIConstants.API_CUSTOM_SEQUENCE_TYPE_IN);
        // Add custom out-sequence
        addCustomSequenceToRegistry(pathToArchive, registry, regResourcePath, importedApi.getOutSequence(),
                ImportExportConstants.OUT_SEQUENCE_LOCATION, APIConstants.API_CUSTOM_SEQUENCE_TYPE_OUT);
        // Add custom fault-sequence
        addCustomSequenceToRegistry(pathToArchive, registry, regResourcePath, importedApi.getFaultSequence(),
                ImportExportConstants.FAULT_SEQUENCE_LOCATION, APIConstants.API_CUSTOM_SEQUENCE_TYPE_FAULT);
    }

    /**
     * @param pathToArchive         Location of the extracted folder of the API
     * @param registry              Registry
     * @param regResourcePath       Resource path in the registry
     * @param sequenceFileName      File name of the sequence
     * @param sequenceLocation      Location of the sequence file
     * @param apiCustomSequenceType Custom sequence type (can be in, out or fault)
     */
    private static void addCustomSequenceToRegistry(String pathToArchive, Registry registry, String regResourcePath,
            String sequenceFileName, String sequenceLocation, String apiCustomSequenceType) {
        String sequenceFileLocation =
                pathToArchive + sequenceLocation + ImportExportConstants.CUSTOM_TYPE + File.separator
                        + sequenceFileName;
        // Adding sequence, if any
        if (CommonUtil.checkFileExistence(sequenceFileLocation + APIConstants.XML_EXTENSION)) {
            String sequencePath = apiCustomSequenceType + RegistryConstants.PATH_SEPARATOR + sequenceFileName;
            addSequenceToRegistry(true, registry, sequenceFileLocation + APIConstants.XML_EXTENSION,
                    regResourcePath + sequencePath);
        }
    }

    /**
     * This method adds the sequence files to the registry. This updates the API specific sequences if already exists.
     *
     * @param isAPISpecific        Whether the adding sequence is API specific
     * @param registry             The registry instance
     * @param sequenceFileLocation Location of the sequence file
     * @param regResourcePath      Resource path in the registry
     */
    private static void addSequenceToRegistry(Boolean isAPISpecific, Registry registry, String sequenceFileLocation,
            String regResourcePath) {

        try {
            if (registry.resourceExists(regResourcePath) && !isAPISpecific) {
                if (log.isDebugEnabled()) {
                    log.debug("Sequence already exists in registry path: " + regResourcePath);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Adding Sequence to the registry path : " + regResourcePath);
                }
                File sequenceFile = new File(sequenceFileLocation);
                try (InputStream seqStream = new FileInputStream(sequenceFile);) {
                    byte[] inSeqData = IOUtils.toByteArray(seqStream);
                    Resource inSeqResource = registry.newResource();
                    inSeqResource.setContent(inSeqData);
                    registry.put(regResourcePath, inSeqResource);
                }
            }
        } catch (RegistryException e) {
            //this is logged and ignored because sequences are optional
            log.error("Failed to add sequences into the registry : " + regResourcePath, e);
        } catch (IOException e) {
            //this is logged and ignored because sequences are optional
            log.error("I/O error while writing sequence data to the registry : " + regResourcePath, e);
        }
    }

    /**
     * This method adds the WSDL to the registry, if there is a WSDL associated with the API.
     *
     * @param pathToArchive Location of the extracted folder of the API
     * @param importedApi   The imported API object
     * @param apiProvider   API Provider
     * @param registry      Registry
     */
    private static void addAPIWsdl(String pathToArchive, API importedApi, APIProvider apiProvider, Registry registry) {

        String wsdlFileName = importedApi.getId().getApiName() + "-" + importedApi.getId().getVersion()
                + APIConstants.WSDL_FILE_EXTENSION;
        String wsdlPath = pathToArchive + ImportExportConstants.WSDL_LOCATION + wsdlFileName;

        if (CommonUtil.checkFileExistence(wsdlPath)) {
            try {
                URL wsdlFileUrl = new File(wsdlPath).toURI().toURL();
                importedApi.setWsdlUrl(wsdlFileUrl.toString());
                APIUtil.createWSDL(registry, importedApi);
                apiProvider.updateAPI(importedApi);
            } catch (MalformedURLException e) {
                // this exception is logged and ignored since WSDL is optional for an API
                log.error("Error in getting WSDL URL. ", e);
            } catch (org.wso2.carbon.registry.core.exceptions.RegistryException e) {
                // this exception is logged and ignored since WSDL is optional for an API
                log.error("Error in putting the WSDL resource to registry. ", e);
            } catch (APIManagementException e) {
                // this exception is logged and ignored since WSDL is optional for an API
                log.error("Error in creating the WSDL resource in the registry. ", e);
            } catch (FaultGatewaysException e) {
                // This is logged and process is continued because WSDL is optional for an API
                log.error("Failed to update API after adding WSDL. ", e);
            }
        }
    }

    /**
     * This method import endpoint certificate.
     *
     * @param pathToArchive location of the extracted folder of the API
     * @param importedApi   the imported API object
     * @throws APIImportExportException If an error occurs while importing endpoint certificates from file
     */
    private static void addEndpointCertificates(String pathToArchive, API importedApi, APIProvider apiProvider,
            int tenantId) throws APIImportExportException {

        String jsonContent = null;
        String pathToEndpointsCertificatesDirectory =
                pathToArchive + File.separator + ImportExportConstants.ENDPOINT_CERTIFICATES_DIRECTORY;
        String pathToYamlFile = pathToEndpointsCertificatesDirectory + ImportExportConstants.ENDPOINTS_CERTIFICATE_FILE
                + ImportExportConstants.YAML_EXTENSION;
        String pathToJsonFile = pathToEndpointsCertificatesDirectory + ImportExportConstants.ENDPOINTS_CERTIFICATE_FILE
                + ImportExportConstants.JSON_EXTENSION;
        try {
            // try loading file as YAML
            if (CommonUtil.checkFileExistence(pathToYamlFile)) {
                if (log.isDebugEnabled()) {
                    log.debug("Found certificate file " + pathToYamlFile);
                }
                String yamlContent = FileUtils.readFileToString(new File(pathToYamlFile));
                jsonContent = CommonUtil.yamlToJson(yamlContent);
            } else if (CommonUtil.checkFileExistence(pathToJsonFile)) {
                // load as a json fallback
                if (log.isDebugEnabled()) {
                    log.debug("Found certificate file " + pathToJsonFile);
                }
                jsonContent = FileUtils.readFileToString(new File(pathToJsonFile));
            }
            if (jsonContent == null) {
                log.debug("No certificate file found to be added, skipping certificate import.");
                return;
            }
            JsonElement configElement = new JsonParser().parse(jsonContent).getAsJsonObject().get(APIConstants.DATA);
            JsonArray certificates = addFileContentToCertificates(configElement.getAsJsonArray(),
                    pathToEndpointsCertificatesDirectory);
            for (JsonElement certificate : certificates) {
                updateAPIWithCertificate(certificate, apiProvider, importedApi, tenantId);
            }
        } catch (IOException e) {
            String errorMessage = "Error in reading certificates file";
            throw new APIImportExportException(errorMessage, e);
        }
    }

    /**
     * Add the certificate content to the object.
     *
     * @param certificates                Certificates array
     * @param pathToCertificatesDirectory File path to the certificates directory
     * @throws IOException If an error occurs while retrieving the certificate content from the file
     */
    private static JsonArray addFileContentToCertificates(JsonArray certificates, String pathToCertificatesDirectory)
            throws IOException {
        JsonArray modifiedCertificates = new JsonArray();
        for (JsonElement certificate : certificates) {
            JsonObject certificateObject = certificate.getAsJsonObject();
            String certificateFileName = certificateObject.get(ImportExportConstants.CERTIFICATE_FILE).getAsString();
            // Get the content of the certificate file from the relevant certificate file inside the certificates
            // directory and add it to the certificate
            String certificateContent = getFileContentOfCertificate(certificateFileName, pathToCertificatesDirectory);
            if (certificateObject.has(ImportExportConstants.CERTIFICATE_CONTENT_JSON_KEY)) {
                certificateObject.remove(ImportExportConstants.CERTIFICATE_CONTENT_JSON_KEY);
            }
            certificateObject.addProperty(ImportExportConstants.CERTIFICATE_CONTENT_JSON_KEY, certificateContent);
            modifiedCertificates.add(certificateObject);
        }
        return modifiedCertificates;
    }

    /**
     * Get the file content of a certificate in the Client-certificate directory.
     *
     * @param certificateFileName         Certificate file name
     * @param pathToCertificatesDirectory Path to client certificates directory
     * @return content of the certificate
     */
    private static String getFileContentOfCertificate(String certificateFileName, String pathToCertificatesDirectory)
            throws IOException {
        String certificateContent = null;
        File certificatesDirectory = new File(pathToCertificatesDirectory);
        File[] certificatesDirectoryListing = certificatesDirectory.listFiles();
        // Iterate the Endpoints certificates directory to get the relevant cert file
        if (certificatesDirectoryListing != null) {
            for (File endpointsCertificate : certificatesDirectoryListing) {
                if (StringUtils.equals(certificateFileName, endpointsCertificate.getName())) {
                    certificateContent = FileUtils.readFileToString(
                            new File(pathToCertificatesDirectory + File.separator + certificateFileName));
                    certificateContent = certificateContent.replace(APIConstants.BEGIN_CERTIFICATE_STRING, "");
                    certificateContent = certificateContent.replace(APIConstants.END_CERTIFICATE_STRING, "");
                }
            }
        }
        return certificateContent;
    }

    /**
     * Update API with the certificate.
     * If certificate alias already exists for tenant in database, certificate content will be
     * updated in trust store. If cert alias does not exits in database for that tenant, add the certificate to
     * publisher and gateway nodes. In such case if alias already exits in the trust store, update the certificate
     * content for that alias.
     *
     * @param certificate Certificate JSON element
     * @param apiProvider API Provider
     * @param importedApi API to import
     * @param tenantId    Tenant Id
     */
    private static void updateAPIWithCertificate(JsonElement certificate, APIProvider apiProvider, API importedApi,
            int tenantId) throws APIImportExportException {
        String certificateFileName = certificate.getAsJsonObject().get(ImportExportConstants.CERTIFICATE_FILE)
                .getAsString();
        String certificateContent = certificate.getAsJsonObject()
                .get(ImportExportConstants.CERTIFICATE_CONTENT_JSON_KEY).getAsString();
        if (certificateContent == null) {
            throw new APIImportExportException("Certificate " + certificateFileName + "is null");
        }
        String alias = certificate.getAsJsonObject().get(ImportExportConstants.ALIAS_JSON_KEY).getAsString();
        String endpoint = certificate.getAsJsonObject().get(ImportExportConstants.ENDPOINT_JSON_KEY).getAsString();
        try {
            if (apiProvider.isCertificatePresent(tenantId, alias) || (
                    ResponseCode.ALIAS_EXISTS_IN_TRUST_STORE.getResponseCode() == (apiProvider
                            .addCertificate(APIUtil.replaceEmailDomainBack(importedApi.getId().getProviderName()),
                                    certificateContent, alias, endpoint)))) {
                apiProvider.updateCertificate(certificateContent, alias);
            }
        } catch (APIManagementException e) {
            String errorMessage = "Error while importing certificate endpoint [" + endpoint + " ]" + "alias [" + alias
                    + " ] tenant user [" + APIUtil.replaceEmailDomainBack(importedApi.getId().getProviderName()) + "]";
            log.error(errorMessage, e);
        }
    }

    /**
     * Import client certificates for Mutual SSL related configuration
     *
     * @param pathToArchive Location of the extracted folder of the API
     * @param apiProvider   API Provider
     * @throws APIImportExportException
     */
    private static void addClientCertificates(String pathToArchive, APIProvider apiProvider)
            throws APIImportExportException {
        String jsonContent = null;
        String pathToClientCertificatesDirectory =
                pathToArchive + File.separator + ImportExportConstants.CLIENT_CERTIFICATES_DIRECTORY;
        String pathToYamlFile = pathToClientCertificatesDirectory + ImportExportConstants.CLIENT_CERTIFICATE_FILE
                + ImportExportConstants.YAML_EXTENSION;
        String pathToJsonFile = pathToClientCertificatesDirectory + ImportExportConstants.CLIENT_CERTIFICATE_FILE
                + ImportExportConstants.JSON_EXTENSION;

        try {
            // try loading file as YAML
            if (CommonUtil.checkFileExistence(pathToYamlFile)) {
                log.debug("Found client certificate file " + pathToYamlFile);
                String yamlContent = FileUtils.readFileToString(new File(pathToYamlFile));
                jsonContent = CommonUtil.yamlToJson(yamlContent);
            } else if (CommonUtil.checkFileExistence(pathToJsonFile)) {
                // load as a json fallback
                log.debug("Found client certificate file " + pathToJsonFile);
                jsonContent = FileUtils.readFileToString(new File(pathToJsonFile));
            }
            if (jsonContent == null) {
                log.debug("No client certificate file found to be added, skipping");
                return;
            }
            JsonElement configElement = new JsonParser().parse(jsonContent).getAsJsonObject().get(APIConstants.DATA);
            JsonArray modifiedCertificatesData = addFileContentToCertificates(configElement.getAsJsonArray(),
                    pathToClientCertificatesDirectory);

            Gson gson = new Gson();
            List<ClientCertificateDTO> certificateMetadataDTOS = gson
                    .fromJson(modifiedCertificatesData, new TypeToken<ArrayList<ClientCertificateDTO>>() {
                    }.getType());
            for (ClientCertificateDTO certDTO : certificateMetadataDTOS) {
                apiProvider.addClientCertificate(
                        APIUtil.replaceEmailDomainBack(certDTO.getApiIdentifier().getProviderName()),
                        certDTO.getApiIdentifier(), certDTO.getCertificate(), certDTO.getAlias(),
                        certDTO.getTierName());
            }
        } catch (IOException e) {
            String errorMessage = "Error in reading certificates file";
            throw new APIImportExportException(errorMessage, e);
        } catch (APIManagementException e) {
            String errorMessage = "Error while importing client certificate";
            throw new APIImportExportException(errorMessage, e);
        }
    }

    /**
     * This method adds API sequences to the imported API. If the sequence is a newly defined one, it is added.
     *
     * @param pathToArchive Location of the extracted folder of the API
     * @param importedApi   API
     * @param registry      Registry
     * @throws APIImportExportException If an error occurs while importing mediation logic
     */
    private static void addSOAPToREST(String pathToArchive, API importedApi, Registry registry)
            throws APIImportExportException {

        String inFlowFileLocation = pathToArchive + File.separator + SOAPTOREST + File.separator + IN;
        String outFlowFileLocation = pathToArchive + File.separator + SOAPTOREST + File.separator + OUT;

        // Adding in-sequence, if any
        if (CommonUtil.checkFileExistence(inFlowFileLocation)) {
            APIIdentifier apiId = importedApi.getId();
            String soapToRestLocationIn =
                    APIConstants.API_ROOT_LOCATION + RegistryConstants.PATH_SEPARATOR + apiId.getProviderName()
                            + RegistryConstants.PATH_SEPARATOR + apiId.getApiName() + RegistryConstants.PATH_SEPARATOR
                            + apiId.getVersion() + RegistryConstants.PATH_SEPARATOR
                            + SOAPToRESTConstants.SequenceGen.SOAP_TO_REST_IN_RESOURCE;
            String soapToRestLocationOut =
                    APIConstants.API_ROOT_LOCATION + RegistryConstants.PATH_SEPARATOR + apiId.getProviderName()
                            + RegistryConstants.PATH_SEPARATOR + apiId.getApiName() + RegistryConstants.PATH_SEPARATOR
                            + apiId.getVersion() + RegistryConstants.PATH_SEPARATOR
                            + SOAPToRESTConstants.SequenceGen.SOAP_TO_REST_OUT_RESOURCE;
            try {
                // Import inflow mediation logic
                Path inFlowDirectory = Paths.get(inFlowFileLocation);
                importMediationLogic(inFlowDirectory, registry, soapToRestLocationIn);

                // Import outflow mediation logic
                Path outFlowDirectory = Paths.get(outFlowFileLocation);
                importMediationLogic(outFlowDirectory, registry, soapToRestLocationOut);

            } catch (DirectoryIteratorException e) {
                throw new APIImportExportException("Error in importing SOAP to REST mediation logic", e);
            }
        }
    }

    /**
     * Method created to add inflow and outflow mediation logic
     *
     * @param flowDirectory      Inflow and outflow directory
     * @param registry           Registry
     * @param soapToRestLocation Folder location
     * @throws APIImportExportException If an error occurs while importing/storing SOAP to REST mediation logic
     */
    private static void importMediationLogic(Path flowDirectory, Registry registry, String soapToRestLocation)
            throws APIImportExportException {
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(flowDirectory)) {
            for (Path file : stream) {
                String fileName = file.getFileName().toString();
                String method = "";
                if (fileName.split(".xml").length != 0) {
                    method = fileName.split(".xml")[0].substring(file.getFileName().toString().lastIndexOf("_") + 1);
                }
                try (InputStream inputFlowStream = new FileInputStream(file.toFile())) {
                    byte[] inSeqData = IOUtils.toByteArray(inputFlowStream);
                    Resource inSeqResource = (Resource) registry.newResource();
                    inSeqResource.setContent(inSeqData);
                    inSeqResource.addProperty(SOAPToRESTConstants.METHOD, method);
                    inSeqResource.setMediaType("text/xml");
                    registry.put(soapToRestLocation + RegistryConstants.PATH_SEPARATOR + file.getFileName(),
                            inSeqResource);
                }
            }
        } catch (IOException | DirectoryIteratorException e) {
            throw new APIImportExportException("Error in importing SOAP to REST mediation logic", e);
        } catch (RegistryException e) {
            throw new APIImportExportException("Error in storing imported SOAP to REST mediation logic", e);
        }
    }

    /**
     * This method returns the lifecycle action which can be used to transit from currentStatus to targetStatus.
     *
     * @param tenantDomain  Tenant domain
     * @param currentStatus Current status to do status transition
     * @param targetStatus  Target status to do status transition
     * @return Lifecycle action or null if target is not reachable
     * @throws APIImportExportException If getting lifecycle action failed
     */
    public static String getLifeCycleAction(String tenantDomain, String currentStatus, String targetStatus,
            APIProvider provider) throws APIImportExportException {

        // No need to change the lifecycle if both the statuses are same
        if (StringUtils.equalsIgnoreCase(currentStatus, targetStatus)) {
            return null;
        }
        LifeCycle lifeCycle = new LifeCycle();
        // Parse DOM of APILifeCycle
        try {
            String data = provider.getLifecycleConfiguration(tenantDomain);
            DocumentBuilderFactory factory = APIUtil.getSecuredDocumentBuilder();
            DocumentBuilder builder = factory.newDocumentBuilder();
            ByteArrayInputStream inputStream = new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));
            Document doc = builder.parse(inputStream);
            Element root = doc.getDocumentElement();

            // Get all nodes with state
            NodeList states = root.getElementsByTagName("state");
            int nStates = states.getLength();
            for (int i = 0; i < nStates; i++) {
                Node node = states.item(i);
                Node id = node.getAttributes().getNamedItem("id");
                if (id != null && !id.getNodeValue().isEmpty()) {
                    LifeCycleTransition lifeCycleTransition = new LifeCycleTransition();
                    NodeList transitions = node.getChildNodes();
                    int nTransitions = transitions.getLength();
                    for (int j = 0; j < nTransitions; j++) {
                        Node transition = transitions.item(j);
                        // Add transitions
                        if (APIImportExportConstants.NODE_TRANSITION.equals(transition.getNodeName())) {
                            Node target = transition.getAttributes().getNamedItem("target");
                            Node action = transition.getAttributes().getNamedItem("event");
                            if (target != null && action != null) {
                                lifeCycleTransition
                                        .addTransition(target.getNodeValue().toLowerCase(), action.getNodeValue());
                            }
                        }
                    }
                    lifeCycle.addLifeCycleState(id.getNodeValue().toLowerCase(), lifeCycleTransition);
                }
            }
        } catch (ParserConfigurationException | SAXException e) {
            String errorMessage = "Error parsing APILifeCycle for tenant: " + tenantDomain;
            throw new APIImportExportException(errorMessage, e);
        } catch (UnsupportedEncodingException e) {
            String errorMessage = "Error parsing unsupported encoding for APILifeCycle in tenant: " + tenantDomain;
            throw new APIImportExportException(errorMessage, e);
        } catch (IOException e) {
            String errorMessage = "Error reading APILifeCycle for tenant: " + tenantDomain;
            throw new APIImportExportException(errorMessage, e);
        } catch (APIManagementException e) {
            String errorMessage = "Error retrieving APILifeCycle for tenant: " + tenantDomain;
            throw new APIImportExportException(errorMessage, e);
        }

        // Retrieve lifecycle action
        LifeCycleTransition transition = lifeCycle.getTransition(currentStatus.toLowerCase());
        if (transition != null) {
            return transition.getAction(targetStatus.toLowerCase());
        }
        return null;
    }
}
