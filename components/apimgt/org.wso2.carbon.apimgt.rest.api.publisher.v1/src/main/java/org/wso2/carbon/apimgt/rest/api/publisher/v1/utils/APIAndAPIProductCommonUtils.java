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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonParseException;
import com.google.gson.reflect.TypeToken;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.APIProvider;
import org.wso2.carbon.apimgt.api.FaultGatewaysException;
import org.wso2.carbon.apimgt.api.dto.ClientCertificateDTO;
import org.wso2.carbon.apimgt.api.model.*;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.certificatemgt.CertificateManager;
import org.wso2.carbon.apimgt.impl.certificatemgt.CertificateManagerImpl;
import org.wso2.carbon.apimgt.impl.importexport.APIImportExportConstants;
import org.wso2.carbon.apimgt.impl.importexport.APIImportExportException;
import org.wso2.carbon.apimgt.impl.importexport.ExportFormat;
import org.wso2.carbon.apimgt.impl.importexport.lifecycle.LifeCycle;
import org.wso2.carbon.apimgt.impl.importexport.lifecycle.LifeCycleTransition;
import org.wso2.carbon.apimgt.impl.importexport.utils.CommonUtil;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.rest.api.publisher.v1.dto.DocumentListDTO;
import org.wso2.carbon.apimgt.rest.api.publisher.v1.utils.mappings.DocumentationMappingUtil;
import org.wso2.carbon.apimgt.rest.api.util.RestApiConstants;
import org.wso2.carbon.apimgt.rest.api.util.utils.RestApiUtil;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.registry.api.Registry;
import org.wso2.carbon.registry.api.RegistryException;
import org.wso2.carbon.registry.api.Resource;
import org.wso2.carbon.registry.core.RegistryConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.xml.sax.SAXException;

import javax.ws.rs.core.Response;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * This is the util class which consists of all the functions for exporting API Product.
 */
public class APIAndAPIProductCommonUtils {

    private static final Log log = LogFactory.getLog(APIAndAPIProductCommonUtils.class);

    /**
     * Exports an API or an API Product from API Manager. Meta information, API icon, documentation, client certificates, WSDL
     * and sequences are exported. This service generates a zipped archive which contains all the above mentioned
     * resources for a given API.
     *
     * @param name           Name of the API that needs to be exported
     * @param version        Version of the API that needs to be exported
     * @param providerName   Provider name of the API that needs to be exported
     * @param format         Format of output documents. Can be YAML or JSON
     * @param preserveStatus Preserve API status on export
     * @param type           Whether an API or an API Product
     * @return Zipped file containing exported API
     */
    public Response exportApiOrApiProductByParams(String name, String version, String providerName, String format, Boolean preserveStatus, String type) {
        ExportFormat exportFormat;
        String userName;
        APIProvider apiProvider;
        String apiDomain;
        String apiRequesterDomain;
        File file;
        //If not specified status is preserved by default
        boolean isStatusPreserved = preserveStatus == null || preserveStatus;

        if (name == null || version == null) {
            RestApiUtil.handleBadRequest("'name' (" + name + ") or 'version' (" + version
                    + ") should not be null.", log);
        }

        try {
            //Default export format is YAML
            exportFormat = StringUtils.isNotEmpty(format) ? ExportFormat.valueOf(format.toUpperCase()) :
                    ExportFormat.YAML;

            // Get currently logged in user's username and the domain
            userName = RestApiUtil.getLoggedInUsername();
            apiRequesterDomain = RestApiUtil.getLoggedInUserTenantDomain();

            // If provider name is not given
            if (StringUtils.isBlank(providerName)) {
                // Retrieve the provider who is in same tenant domain and who owns the same API (by comparing
                // API name and the version)
                providerName = APIUtil.getAPIProviderFromAPINameVersionTenant(name, version, apiRequesterDomain);

                // If there is no provider in current domain, the API cannot be exported
                if (providerName == null) {
                    String errorMessage = "Error occurred while exporting. API: " + name + " version: " + version
                            + " not found";
                    RestApiUtil.handleResourceNotFoundError(errorMessage, log);
                }
            }

            //provider names with @ signs are only accepted
            apiDomain = MultitenantUtils.getTenantDomain(providerName);

            if (!StringUtils.equals(apiDomain, apiRequesterDomain)) {
                //not authorized to export requested API
                RestApiUtil.handleAuthorizationFailure(RestApiConstants.RESOURCE_API +
                        " name:" + name + " version:" + version + " provider:" + providerName, log);
            }

            apiProvider = RestApiUtil.getLoggedInUserProvider();
            if (!StringUtils.equals(type, RestApiConstants.RESOURCE_API_PRODUCT)) {
                APIIdentifier apiIdentifier = new APIIdentifier(APIUtil.replaceEmailDomain(providerName), name, version);
                // Checking whether the API exists
                if (!apiProvider.isAPIAvailable(apiIdentifier)) {
                    String errorMessage = "Error occurred while exporting. API: " + name + " version: " + version
                            + " not found";
                    RestApiUtil.handleResourceNotFoundError(errorMessage, log);
                }
                file = ExportApiUtils.exportApi(apiProvider, apiIdentifier, userName, exportFormat, isStatusPreserved);
            } else {
                APIProductIdentifier apiProductIdentifier = new APIProductIdentifier(APIUtil.replaceEmailDomain(providerName),
                        name, version);
                // Checking whether the API Product exists
                if (!apiProvider.isAPIProductAvailable(apiProductIdentifier)) {
                    String errorMessage = "Error occurred while exporting. API Product: " + name + " version: " + version
                            + " not found";
                    RestApiUtil.handleResourceNotFoundError(errorMessage, log);
                }
                file = ExportAPIProductUtils.exportApiProduct(apiProvider, apiProductIdentifier, userName, exportFormat,
                        isStatusPreserved);
            }
            return Response.ok(file)
                    .header(RestApiConstants.HEADER_CONTENT_DISPOSITION, "attachment; filename=\""
                            + file.getName() + "\"")
                    .build();
        } catch (APIManagementException | APIImportExportException e) {
            RestApiUtil.handleInternalServerError("Error while exporting " + RestApiConstants.RESOURCE_API, e, log);
        }
        return null;
    }

    /**
     * Retrieve thumbnail image for the exporting API or API Product and store it in the archive directory.
     *
     * @param identifier ID of the requesting API or API Product
     * @param registry   Current tenant registry
     * @throws APIImportExportException If an error occurs while retrieving image from the registry or
     *                                  storing in the archive directory
     */
    public static void exportAPIOrAPIProductThumbnail(String archivePath, Identifier identifier, Registry registry)
            throws APIImportExportException {
        String thumbnailUrl = APIConstants.API_IMAGE_LOCATION + RegistryConstants.PATH_SEPARATOR
                + identifier.getProviderName() + RegistryConstants.PATH_SEPARATOR + identifier.getName()
                + RegistryConstants.PATH_SEPARATOR + identifier.getVersion() + RegistryConstants.PATH_SEPARATOR
                + APIConstants.API_ICON_IMAGE;
        String localImagePath = archivePath + File.separator + APIImportExportConstants.IMAGE_RESOURCE;
        try {
            if (registry.resourceExists(thumbnailUrl)) {
                Resource icon = registry.get(thumbnailUrl);
                String mediaType = icon.getMediaType();
                String extension = APIImportExportConstants.fileExtensionMapping.get(mediaType);
                if (extension != null) {
                    CommonUtil.createDirectory(localImagePath);
                    try (InputStream imageDataStream = icon.getContentStream();
                         OutputStream outputStream = new FileOutputStream(localImagePath + File.separator
                                 + APIConstants.API_ICON_IMAGE + APIConstants.DOT + extension)) {
                        IOUtils.copy(imageDataStream, outputStream);
                        if (log.isDebugEnabled()) {
                            log.debug("Thumbnail image retrieved successfully for API/API Product: " + identifier.getName()
                                    + StringUtils.SPACE + APIConstants.API_DATA_VERSION + ": "
                                    + identifier.getVersion());
                        }
                    }
                } else {
                    //api gets imported without thumbnail
                    log.error("Unsupported media type for icon " + mediaType + ". Skipping thumbnail export.");
                }
            } else if (log.isDebugEnabled()) {
                log.debug("Thumbnail URL [" + thumbnailUrl + "] does not exists in registry for API/API Product: "
                        + identifier.getName() + StringUtils.SPACE + APIConstants.API_DATA_VERSION + ": "
                        + identifier.getVersion() + ". Skipping thumbnail export.");
            }
        } catch (RegistryException e) {
            log.error("Error while retrieving API/API Product Thumbnail " + thumbnailUrl, e);
        } catch (IOException e) {
            //Exception is ignored by logging due to the reason that Thumbnail is not essential for
            //an API to be recreated.
            log.error("I/O error while writing API/API Product Thumbnail: " + thumbnailUrl + " to file", e);
        }
    }

    /**
     * Retrieve documentation for the exporting API or API Product and store it in the archive directory.
     * FILE, INLINE, MARKDOWN and URL documentations are handled.
     *
     * @param identifier   ID of the requesting API or API Product
     * @param registry     Current tenant registry
     * @param docList      Documentation list of the exporting API or API Product
     * @param exportFormat Format for export
     * @throws APIImportExportException If an error occurs while retrieving documents from the
     *                                  registry or storing in the archive directory
     */
    public static void exportAPIOrAPIProductDocumentation(String archivePath, List<Documentation> docList,
                                                          Identifier identifier, Registry registry, ExportFormat exportFormat)
            throws APIImportExportException {

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String docDirectoryPath = File.separator + APIImportExportConstants.DOCUMENT_DIRECTORY;
        CommonUtil.createDirectory(archivePath + docDirectoryPath);
        try {
            for (Documentation doc : docList) {
                String sourceType = doc.getSourceType().name();
                String resourcePath = null;
                String localFileName = null;
                docDirectoryPath = File.separator + APIImportExportConstants.DOCUMENT_DIRECTORY;
                if (Documentation.DocumentSourceType.FILE.toString().equalsIgnoreCase(sourceType)) {
                    localFileName = doc.getFilePath().substring(
                            doc.getFilePath().lastIndexOf(RegistryConstants.PATH_SEPARATOR) + 1);
                    resourcePath = APIUtil.getDocumentationFilePath(identifier, localFileName);
                    docDirectoryPath += File.separator + APIImportExportConstants.FILE_DOCUMENT_DIRECTORY;
                    doc.setFilePath(localFileName);
                } else if (Documentation.DocumentSourceType.INLINE.toString().equalsIgnoreCase(sourceType)
                        || Documentation.DocumentSourceType.MARKDOWN.toString().equalsIgnoreCase(sourceType)) {
                    //Inline/Markdown content file name would be same as the documentation name
                    //Markdown content files will also be stored in InlineContents directory
                    localFileName = doc.getName();
                    resourcePath = APIUtil.getAPIOrAPIProductDocPath(identifier) + APIConstants.INLINE_DOCUMENT_CONTENT_DIR
                            + RegistryConstants.PATH_SEPARATOR + localFileName;
                    docDirectoryPath += File.separator + APIImportExportConstants.INLINE_DOCUMENT_DIRECTORY;
                }

                if (resourcePath != null) {
                    //Write content separately for Inline/Markdown/File type documentations only
                    //check whether resource exists in the registry
                    if (registry.resourceExists(resourcePath)) {
                        CommonUtil.createDirectory(archivePath + docDirectoryPath);
                        String localFilePath = docDirectoryPath + File.separator + localFileName;
                        Resource docFile = registry.get(resourcePath);
                        try (OutputStream outputStream = new FileOutputStream(archivePath + localFilePath);
                             InputStream fileInputStream = docFile.getContentStream()) {
                            IOUtils.copy(fileInputStream, outputStream);
                        }
                    } else {
                        //Log error and avoid throwing as we give capability to export document artifact without the
                        //content if does not exists
                        String errorMessage = "Documentation resource for API/API Product: " + identifier.getName()
                                + " not found in " + resourcePath;
                        log.error(errorMessage);
                    }
                }
            }

            DocumentListDTO documentListDTO = DocumentationMappingUtil.fromDocumentationListToDTO(docList, 0,
                    docList.size());
            JsonObject documentJsonObject = APIAndAPIProductCommonUtils.addTypeAndVersionToFile(
                    APIImportExportConstants.TYPE_DOCUMENTS, APIImportExportConstants.APIM_VERSION,
                    gson.toJsonTree(documentListDTO));
            String json = gson.toJson(documentJsonObject);
            switch (exportFormat) {
                case JSON:
                    CommonUtil.writeFile(archivePath + APIImportExportConstants.JSON_DOCUMENT_FILE_LOCATION, json);
                    break;
                case YAML:
                    String yaml = CommonUtil.jsonToYaml(json);
                    CommonUtil.writeFile(archivePath + APIImportExportConstants.YAML_DOCUMENT_FILE_LOCATION, yaml);
                    break;
            }

            if (log.isDebugEnabled()) {
                log.debug("Documentation retrieved successfully for API/API Product: " + identifier.getName()
                        + StringUtils.SPACE + APIConstants.API_DATA_VERSION + ": " + identifier.getVersion());
            }
        } catch (IOException e) {
            String errorMessage = "I/O error while writing documentation to file for API/API Product: "
                    + identifier.getName() + StringUtils.SPACE + APIConstants.API_DATA_VERSION + ": "
                    + identifier.getVersion();
            log.error(errorMessage, e);
            throw new APIImportExportException(errorMessage, e);
        } catch (RegistryException e) {
            String errorMessage = "Error while retrieving documentation for API/API Product: " + identifier.getName()
                    + StringUtils.SPACE + APIConstants.API_DATA_VERSION + ": " + identifier.getVersion();
            log.error(errorMessage, e);
            throw new APIImportExportException(errorMessage, e);
        }
    }

    /**
     * Retrieve API Definition as JSON.
     *
     * @param pathToArchive Path to API or API Product archive
     * @throws IOException If an error occurs while reading the file
     */
    public static String getAPIDefinitionAsJson(String pathToArchive) throws IOException {
        String jsonContent = null;
        String pathToYamlFile = pathToArchive + APIImportExportConstants.YAML_API_FILE_LOCATION;
        String pathToJsonFile = pathToArchive + APIImportExportConstants.JSON_API_FILE_LOCATION;

        // load yaml representation first if it is present
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
     * Export Mutual SSL related certificates
     *
     * @param apiTypeWrapper API or API Product to be exported
     * @param tenantId       Tenant id of the user
     * @param provider       Api Provider
     * @param exportFormat   Export format of file
     * @throws APIImportExportException
     */
    public static void exportClientCertificates(String archivePath, ApiTypeWrapper apiTypeWrapper, int tenantId, APIProvider provider,
                                                ExportFormat exportFormat) throws APIImportExportException {

        List<ClientCertificateDTO> certificateMetadataDTOs;
        try {
            if (apiTypeWrapper.isAPIProduct()) {
                certificateMetadataDTOs = provider.searchClientCertificates(tenantId, null, apiTypeWrapper.getApiProduct().getId());
            } else {
                certificateMetadataDTOs = provider.searchClientCertificates(tenantId, null, apiTypeWrapper.getApi().getId());
            }
            if (certificateMetadataDTOs.isEmpty()) {
                return;
            }
            String clientCertsDirectoryPath = archivePath + File.separator
                    + APIImportExportConstants.CLIENT_CERTIFICATES_DIRECTORY;
            CommonUtil.createDirectory(clientCertsDirectoryPath);

            JsonArray certificateList = getClientCertificateContentAndMetaData(certificateMetadataDTOs, clientCertsDirectoryPath);

            if (certificateList.size() > 0) {
                Gson gson = new GsonBuilder().setPrettyPrinting().create();
                JsonObject clientCertificatesJsonObject = APIAndAPIProductCommonUtils.addTypeAndVersionToFile(
                        APIImportExportConstants.TYPE_CLIENT_CERTIFICATES, APIImportExportConstants.APIM_VERSION,
                        gson.toJsonTree(certificateList));
                String certificatesJson = gson.toJson(clientCertificatesJsonObject);
                switch (exportFormat) {
                    case YAML:
                        CommonUtil.writeFile(clientCertsDirectoryPath + APIImportExportConstants.YAML_CLIENT_CERTIFICATE_FILE,
                                CommonUtil.jsonToYaml(certificatesJson));
                        break;
                    case JSON:
                        CommonUtil.writeFile(clientCertsDirectoryPath + APIImportExportConstants.JSON_CLIENT_CERTIFICATE_FILE,
                                certificatesJson);
                }
            }
        } catch (IOException e) {
            String errorMessage = "Error while retrieving saving as YAML";
            throw new APIImportExportException(errorMessage, e);
        } catch (APIManagementException e) {
            String errorMsg = "Error retrieving certificate meta data. tenantId [" + tenantId + "] api ["
                    + tenantId + "]";
            throw new APIImportExportException(errorMsg, e);
        }
    }

    /**
     * Replace original provider name from imported API properties with the logged in username
     * This method is used when "preserveProvider" property is set to false.
     *
     * @param apiTypeWrapper Imported API or API Product
     * @param currentDomain  Current domain name
     * @param previousDomain Original domain name
     */
    public static void setCurrentProviderToAPIProperties(ApiTypeWrapper apiTypeWrapper, String currentDomain, String previousDomain) {
        if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equalsIgnoreCase(currentDomain) &&
                !MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equalsIgnoreCase(previousDomain)) {
            apiTypeWrapper.setContext(apiTypeWrapper.getContext().replace(APIConstants.TENANT_PREFIX + previousDomain,
                    StringUtils.EMPTY));
            apiTypeWrapper.setContextTemplate(apiTypeWrapper.getContextTemplate().replace(APIConstants.TENANT_PREFIX
                    + previousDomain, StringUtils.EMPTY));
        } else if (!MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equalsIgnoreCase(currentDomain) &&
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equalsIgnoreCase(previousDomain)) {
            apiTypeWrapper.setContext(APIConstants.TENANT_PREFIX + currentDomain + apiTypeWrapper.getContext());
            apiTypeWrapper.setContextTemplate(APIConstants.TENANT_PREFIX + currentDomain + apiTypeWrapper.getContextTemplate());
        } else if (!StringUtils.equalsIgnoreCase(currentDomain, previousDomain)) {
            apiTypeWrapper.setContext(apiTypeWrapper.getContext().replace(previousDomain, currentDomain));
            apiTypeWrapper.setContextTemplate(apiTypeWrapper.getContextTemplate().replace(previousDomain, currentDomain));
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
                                lifeCycleTransition.addTransition(target.getNodeValue().toLowerCase(), action.getNodeValue());
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

    /**
     * Load a swagger document from archive. This method lookup for swagger as YAML or JSON.
     *
     * @param pathToArchive Path to archive
     * @return Swagger content as a JSON
     * @throws IOException When swagger document not found
     */
    public static String loadSwaggerFile(String pathToArchive) throws IOException {

        if (CommonUtil.checkFileExistence(pathToArchive + APIImportExportConstants.YAML_SWAGGER_DEFINITION_LOCATION)) {
            if (log.isDebugEnabled()) {
                log.debug("Found swagger file " + pathToArchive + APIImportExportConstants.YAML_SWAGGER_DEFINITION_LOCATION);
            }
            String yamlContent = FileUtils.readFileToString(
                    new File(pathToArchive + APIImportExportConstants.YAML_SWAGGER_DEFINITION_LOCATION));
            return CommonUtil.yamlToJson(yamlContent);
        } else if (CommonUtil.checkFileExistence(pathToArchive + APIImportExportConstants.JSON_SWAGGER_DEFINITION_LOCATION)) {
            if (log.isDebugEnabled()) {
                log.debug("Found swagger file " + pathToArchive + APIImportExportConstants.JSON_SWAGGER_DEFINITION_LOCATION);
            }
            return FileUtils.readFileToString(
                    new File(pathToArchive + APIImportExportConstants.JSON_SWAGGER_DEFINITION_LOCATION));
        }
        throw new IOException("Missing swagger file. Either swagger.json or swagger.yaml should present");
    }

    /**
     * This method update the API or API Product with the icon to be displayed at the API store.
     *
     * @param pathToArchive  Location of the extracted folder of the API or API Product
     * @param apiTypeWrapper The imported API object
     */
    public static void addAPIOrAPIProductImage(String pathToArchive, ApiTypeWrapper apiTypeWrapper, APIProvider apiProvider) {

        //Adding image icon to the API if there is any
        File imageFolder = new File(pathToArchive + APIImportExportConstants.IMAGE_FILE_LOCATION);
        File[] fileArray = imageFolder.listFiles();
        if (imageFolder.isDirectory() && fileArray != null) {
            //This loop locates the icon of the API
            for (File imageFile : fileArray) {
                if (imageFile != null && imageFile.getName().contains(APIConstants.API_ICON_IMAGE)) {
                    updateAPIOrAPIProductWithThumbnail(imageFile, apiTypeWrapper, apiProvider);
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
    private static void updateAPIOrAPIProductWithThumbnail(File imageFile, ApiTypeWrapper apiTypeWrapper, APIProvider apiProvider) {

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
            apiTypeWrapper.setThumbnailUrl(APIUtil.prependTenantPrefix(thumbnailUrl,
                    identifier.getProviderName()));
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
    public static void addAPIOrAPIProductDocuments(String pathToArchive, ApiTypeWrapper apiTypeWrapper, APIProvider apiProvider) {

        String jsonContent = null;
        String pathToYamlFile = pathToArchive + APIImportExportConstants.YAML_DOCUMENT_FILE_LOCATION;
        String pathToJsonFile = pathToArchive + APIImportExportConstants.JSON_DOCUMENT_FILE_LOCATION;
        Identifier identifier = apiTypeWrapper.getId();
        Documentation[] documentations;
        String docDirectoryPath = pathToArchive + File.separator + APIImportExportConstants.DOCUMENT_DIRECTORY;
        try {
            //remove all documents associated with the API before update
            List<Documentation> documents = apiProvider.getAllDocumentation(identifier);
            if (documents != null) {
                for (Documentation documentation : documents) {
                    apiProvider.removeDocumentation(identifier, documentation.getId());
                }
            }
            //load document file if exists
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
            if (jsonContent == null) {
                if (log.isDebugEnabled()) {
                    log.debug("No document definition found, Skipping documentation import for API/API Product: "
                            + identifier.getName());
                }
                return;
            }

            documentations = new Gson().fromJson(jsonContent, Documentation[].class);
            //For each type of document separate action is performed
            for (Documentation doc : documentations) {

                String docSourceType = doc.getSourceType().toString();
                boolean docContentExists = Documentation.DocumentSourceType.INLINE.toString().equalsIgnoreCase(docSourceType)
                        || Documentation.DocumentSourceType.MARKDOWN.toString().equalsIgnoreCase(docSourceType);
                String inlineContent = null;

                if (docContentExists) {
                    try (FileInputStream inputStream = new FileInputStream(docDirectoryPath + File.separator
                            + APIImportExportConstants.INLINE_DOCUMENT_DIRECTORY + File.separator + doc.getName())) {

                        inlineContent = IOUtils.toString(inputStream, APIImportExportConstants.CHARSET);
                    }
                } else if (APIImportExportConstants.FILE_DOC_TYPE.equalsIgnoreCase(docSourceType)) {
                    String filePath = doc.getFilePath();
                    try (FileInputStream inputStream = new FileInputStream(docDirectoryPath + File.separator
                            + APIImportExportConstants.FILE_DOCUMENT_DIRECTORY + File.separator + filePath)) {
                        String docExtension = FilenameUtils.getExtension(pathToArchive + File.separator
                                + APIImportExportConstants.DOCUMENT_DIRECTORY + File.separator + filePath);
                        ResourceFile apiDocument = new ResourceFile(inputStream, docExtension);
                        String visibleRolesList = apiTypeWrapper.getVisibleRoles();
                        String[] visibleRoles = new String[0];
                        if (visibleRolesList != null) {
                            visibleRoles = visibleRolesList.split(",");
                        }
                        String filePathDoc = APIUtil.getDocumentationFilePath(identifier, filePath);
                        APIUtil.setResourcePermissions(apiTypeWrapper.getId().getProviderName(),
                                apiTypeWrapper.getVisibility(), visibleRoles, filePathDoc);
                        doc.setFilePath(apiProvider.addResourceFile(apiTypeWrapper.getId(), filePathDoc, apiDocument));
                    } catch (FileNotFoundException e) {
                        //this error is logged and ignored because documents are optional in an API
                        log.error("Failed to locate the document files of the API/API Product: " + apiTypeWrapper.getId().getName(), e);
                        continue;
                    }
                }

                //Add documentation accordingly.
                apiProvider.addDocumentation(identifier, doc);

                if (docContentExists) {
                    //APIProvider.addDocumentationContent method handles both create/update documentation content
                    if (!apiTypeWrapper.isAPIProduct()) {
                        apiProvider.addDocumentationContent(apiTypeWrapper.getApi(), doc.getName(), inlineContent);
                    } else {
                        apiProvider.addProductDocumentationContent(apiTypeWrapper.getApiProduct(), doc.getName(), inlineContent);
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
     * Import client certificates for Mutual SSL related configuration
     *
     * @param pathToArchive location of the extracted folder of the API
     * @throws APIImportExportException
     */
    public static void addClientCertificates(String pathToArchive, APIProvider apiProvider)
            throws APIImportExportException {
        String jsonContent = null;
        String pathToYamlFile = pathToArchive + APIImportExportConstants.YAML_CLIENT_CERTIFICATE_FILE;
        String pathToJsonFile = pathToArchive + APIImportExportConstants.JSON_CLIENT_CERTIFICATE_FILE;

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
            Gson gson = new Gson();
            List<ClientCertificateDTO> certificateMetadataDTOS = gson.fromJson(jsonContent,
                    new TypeToken<ArrayList<ClientCertificateDTO>>() {
                    }.getType());
            for (ClientCertificateDTO certDTO : certificateMetadataDTOS) {
                apiProvider.addClientCertificate(
                        APIUtil.replaceEmailDomainBack(certDTO.getApiIdentifier().getProviderName()),
                        certDTO.getApiIdentifier(), certDTO.getCertificate(), certDTO.getAlias(),
                        certDTO.getTierName());
            }
        } catch (IOException e) {
            String errorMessage = "Error in reading " + APIImportExportConstants.YAML_ENDPOINTS_CERTIFICATE_FILE
                    + " file";
            throw new APIImportExportException(errorMessage, e);
        } catch (APIManagementException e) {
            String errorMessage = "Error while importing client certificate";
            throw new APIImportExportException(errorMessage, e);
        }
    }

    /**
     * Set the subscription level tiers of an API/API Product by validating with the tiers available in the environment
     *
     * @param apiJsonContent JSON content of API or API Product to be imported
     * @param apiProvider    API Provider
     * @throws APIImportExportException
     */
    public static void setSubscriptionTiers(JsonObject apiJsonContent, APIProvider apiProvider)
            throws APIManagementException {
        // Retrieve the subscription tier names mentioned in the API
        JsonArray subscriptionTierNames = apiJsonContent.get(APIConstants.SUBSCRIPTION_TIERS).getAsJsonArray();
        // Retrieve the subscription tiers that are already available in the instance
        Set<Tier> allowedTiers = apiProvider.getTiers();

        // An array will be created to store the valid subscription tier details
        JsonArray subscriptionTiers = new JsonArray();
        Gson gson = new GsonBuilder().create();

        // Check whether the subscription tiers are provided or not in the API
        if (subscriptionTierNames != null || subscriptionTierNames.size() > 0) {
            // If provided, iterate the names array, and check whether those are available in the instance
            for (JsonElement subscriptionTierName : subscriptionTierNames) {
                // To store whether the tier is available in the instance
                Boolean tierFound = false;
                if (allowedTiers != null) {
                    // Iterate the available tiers in the instance
                    for (Tier tier : allowedTiers) {
                        // If a tier from the API and a tier from the instance is matched, that can be named as a
                        // valid match ,and the tier will be added to the set and tierFound will be marked as true
                        if (StringUtils.equals(tier.getName(), subscriptionTierName.getAsString())) {
                            subscriptionTiers.add(gson.toJsonTree(tier));
                            tierFound = true;
                        }
                    }
                    // If any of the tiers from the API does not have a valid match from the tiers available in the
                    // instance, an error will be thrown
                    if (!tierFound) {
                        String message = "Invalid Subscription level throttling tier:" + subscriptionTierName.getAsString() +
                                " provided.";
                        throw new APIManagementException(message);
                    }
                }
            }
            // Remove the old tier names array from the apiJsonContent
            apiJsonContent.remove(APIConstants.SUBSCRIPTION_TIERS);
            // Add the new tier array to the apiJsonContent
            apiJsonContent.add(APIConstants.SUBSCRIPTION_TIERS, subscriptionTiers);
        }
    }

    /**
     * Add the type and the version to the artifact file when exporting.
     *
     * @param type        Type of the artifact to be exported
     * @param version     API Manager version
     * @param jsonElement JSON element to be added as data
     */
    public static JsonObject addTypeAndVersionToFile(String type, String version, JsonElement jsonElement) {
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty(APIConstants.TYPE, type);
        jsonObject.addProperty(APIConstants.API_DATA_VERSION, version);
        jsonObject.add(APIConstants.DATA, jsonElement);
        return jsonObject;
    }

    /**
     * Get Client Certificate MetaData and Certificate detail and build JSON list.
     *
     * @param clientCertificateDTOs client certificates list DTOs
     * @param certDirectoryPath     directory path to export the certificates
     * @return list of certificate detail JSON objects
     */
    private static JsonArray getClientCertificateContentAndMetaData(List<ClientCertificateDTO> clientCertificateDTOs,
                                                                    String certDirectoryPath) {
        CertificateManager certificateManager = CertificateManagerImpl.getInstance();
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        JsonArray certificatesList = new JsonArray();
        clientCertificateDTOs.forEach(metadataDTO -> {
            ByteArrayInputStream certificate = null;
            try {
                String certificateContent = metadataDTO.getCertificate();
                String certificateContentEncoded = APIConstants.BEGIN_CERTIFICATE_STRING
                        .concat(certificateContent).concat("\n")
                        .concat(APIConstants.END_CERTIFICATE_STRING);
                CommonUtil.writeFile(certDirectoryPath + File.separator + metadataDTO.getAlias() + ".crt",
                        certificateContentEncoded);
                // Add the file name to the Certificate Metadata
                JsonObject modifiedCertificateMetadata = (JsonObject) gson.toJsonTree(metadataDTO);
                modifiedCertificateMetadata.remove(APIImportExportConstants.CERTIFICATE_CONTENT_JSON_KEY);
                modifiedCertificateMetadata.addProperty("file", metadataDTO.getAlias() + ".crt");
                certificatesList.add(modifiedCertificateMetadata);
            } catch (APIImportExportException e) {
                log.error("Error while writing the certificate content. For alias: " + metadataDTO.getAlias(), e);
            } finally {
                if (certificate != null) {
                    IOUtils.closeQuietly(certificate);
                }
            }
        });
        return certificatesList;
    }
}
