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
import org.wso2.carbon.apimgt.impl.importexport.utils.APIImportUtil;
import org.wso2.carbon.apimgt.impl.importexport.utils.APIProductImportUtil;
import org.wso2.carbon.apimgt.impl.importexport.utils.CommonUtil;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.rest.api.publisher.v1.dto.DocumentDTO;
import org.wso2.carbon.apimgt.rest.api.publisher.v1.dto.DocumentListDTO;
import org.wso2.carbon.apimgt.rest.api.publisher.v1.utils.mappings.APIMappingUtil;
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

public class APIAndAPIProductCommonUtils {
    private static final Log log = LogFactory.getLog(APIAndAPIProductCommonUtils.class);

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
     * @param archivePath   File path to the documents to be exported
     * @param identifier   ID of the requesting API or API Product
     * @param registry     Current tenant registry
     * @param exportFormat Format for export
     * @param apiProvider     API Provider
     * @throws APIImportExportException If an error occurs while retrieving documents from the
     *                                  registry or storing in the archive directory
     * @throws APIManagementException If an error occurs while retrieving document details
     */
    public static void exportAPIOrAPIProductDocumentation(String archivePath, Identifier identifier, Registry registry,
                                                          ExportFormat exportFormat, APIProvider apiProvider)
            throws APIImportExportException, APIManagementException {

        List<Documentation> docList = apiProvider.getAllDocumentation(identifier);
        String tenantDomain = RestApiUtil.getLoggedInUserTenantDomain();
        if (!docList.isEmpty()) {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            String docDirectoryPath = archivePath + File.separator + APIImportExportConstants.DOCUMENT_DIRECTORY;
            CommonUtil.createDirectory(docDirectoryPath);
            try {
                for (Documentation doc : docList) {
                    // Retrieving the document again since objects in docList might have missing fields
                    Documentation individualDocument = apiProvider.getDocumentation(doc.getId(), tenantDomain);
                    String sourceType = individualDocument.getSourceType().name();
                    String resourcePath = null;
                    String localFileName = null;
                    String individualDocDirectoryPath = docDirectoryPath + File.separator + individualDocument.getName();
                    CommonUtil.createDirectory(individualDocDirectoryPath);

                    JsonObject documentJsonObject = addTypeAndVersionToFile(
                            APIImportExportConstants.TYPE_DOCUMENTS, APIImportExportConstants.APIM_VERSION,
                            gson.toJsonTree(DocumentationMappingUtil.fromDocumentationToDTO(individualDocument)));
                    String jsonDocument = gson.toJson(documentJsonObject);
                    writeToYamlOrJson(individualDocDirectoryPath + APIImportExportConstants.DOCUMENT_FILE_NAME,
                            exportFormat, jsonDocument);

                    if (Documentation.DocumentSourceType.FILE.toString().equalsIgnoreCase(sourceType)) {
                        localFileName = individualDocument.getFilePath().substring(
                                individualDocument.getFilePath().lastIndexOf(RegistryConstants.PATH_SEPARATOR) + 1);
                        resourcePath = APIUtil.getDocumentationFilePath(identifier, localFileName);
                        individualDocument.setFilePath(localFileName);
                    } else if (Documentation.DocumentSourceType.INLINE.toString().equalsIgnoreCase(sourceType)
                            || Documentation.DocumentSourceType.MARKDOWN.toString().equalsIgnoreCase(sourceType)) {
                        // Inline/Markdown content file name would be same as the documentation name
                        localFileName = individualDocument.getName();
                        resourcePath = APIUtil.getAPIOrAPIProductDocPath(identifier) + APIConstants.INLINE_DOCUMENT_CONTENT_DIR
                                + RegistryConstants.PATH_SEPARATOR + localFileName;
                    }

                    if (resourcePath != null) {
                        // Write content for Inline/Markdown/File type documentations only
                        // Check whether resource exists in the registry
                        if (registry.resourceExists(resourcePath)) {
                            Resource docFile = registry.get(resourcePath);
                            try (OutputStream outputStream = new FileOutputStream(individualDocDirectoryPath +
                                    File.separator + localFileName);
                                 InputStream fileInputStream = docFile.getContentStream()) {
                                IOUtils.copy(fileInputStream, outputStream);
                            }
                        } else {
                            // Log error and avoid throwing as we give capability to export document artifact without the
                            // content if does not exists
                            String errorMessage = "Documentation resource for API/API Product: " + identifier.getName()
                                    + " not found in " + resourcePath;
                            log.error(errorMessage);
                        }
                    }
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
        } else if (log.isDebugEnabled()) {
            log.debug("No documentation found for API/API Product: " + identifier + ". Skipping documentation export.");
        }
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
                writeToYamlOrJson(clientCertsDirectoryPath + APIImportExportConstants.CLIENT_CERTIFICATE_FILE,
                        exportFormat, certificatesJson);
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
     * Get Client Certificate MetaData and Certificate detail and build JSON list.
     *
     * @param clientCertificateDTOs client certificates list DTOs
     * @param certDirectoryPath     directory path to export the certificates
     * @return list of certificate detail JSON objects
     */
    private static JsonArray getClientCertificateContentAndMetaData(List<ClientCertificateDTO> clientCertificateDTOs,
                                                                    String certDirectoryPath) {
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
     * Write the file content of an API or API related artifact based on the format.
     *
     * @param filePath     Path to the location where the file content should be written
     * @param exportFormat Format to be exported
     * @param fileContent  Content to be written
     */
    public static void writeToYamlOrJson(String filePath, ExportFormat exportFormat, String fileContent)
            throws APIImportExportException, IOException {
        switch (exportFormat) {
            case YAML:
                String fileInYaml = CommonUtil.jsonToYaml(fileContent);
                CommonUtil.writeFile(filePath + APIImportExportConstants.YAML_EXTENSION, fileInYaml);
                break;
            case JSON:
                CommonUtil.writeFile(filePath + APIImportExportConstants.JSON_EXTENSION, fileContent);
        }
    }
}
