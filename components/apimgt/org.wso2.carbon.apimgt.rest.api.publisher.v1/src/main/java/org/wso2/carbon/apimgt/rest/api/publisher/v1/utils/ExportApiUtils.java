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

import com.google.gson.*;
import org.apache.axiom.om.OMElement;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.apimgt.api.APIDefinition;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.APIProvider;
import org.wso2.carbon.apimgt.api.dto.CertificateMetadataDTO;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.APIIdentifier;
import org.wso2.carbon.apimgt.api.model.ApiTypeWrapper;
import org.wso2.carbon.apimgt.api.model.Documentation;
import org.wso2.carbon.apimgt.api.model.Scope;
import org.wso2.carbon.apimgt.api.model.URITemplate;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.APIMRegistryServiceImpl;
import org.wso2.carbon.apimgt.impl.certificatemgt.CertificateManager;
import org.wso2.carbon.apimgt.impl.certificatemgt.CertificateManagerImpl;
import org.wso2.carbon.apimgt.impl.definitions.OASParserUtil;
import org.wso2.carbon.apimgt.impl.importexport.APIImportExportConstants;
import org.wso2.carbon.apimgt.impl.importexport.APIImportExportException;
import org.wso2.carbon.apimgt.impl.importexport.ExportFormat;
import org.wso2.carbon.apimgt.impl.importexport.utils.CommonUtil;
import org.wso2.carbon.apimgt.impl.internal.ServiceReferenceHolder;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.rest.api.publisher.v1.dto.APIDTO;
import org.wso2.carbon.apimgt.rest.api.publisher.v1.utils.mappings.APIMappingUtil;
import org.wso2.carbon.apimgt.rest.api.util.RestApiConstants;
import org.wso2.carbon.apimgt.rest.api.util.utils.RestApiUtil;
import org.wso2.carbon.registry.api.Collection;
import org.wso2.carbon.registry.api.Registry;
import org.wso2.carbon.registry.api.RegistryException;
import org.wso2.carbon.registry.api.Resource;
import org.wso2.carbon.registry.core.RegistryConstants;
import org.wso2.carbon.registry.core.session.UserRegistry;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.ws.rs.core.Response;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ExportApiUtils {
    private static final Log log = LogFactory.getLog(ExportApiUtils.class);
    private static final String IN = "in";
    private static final String OUT = "out";
    private static final String SOAPTOREST = "SoapToRest";

    /**
     * Retrieve thumbnail image for the exporting API and store it in the archive directory.
     *
     * @param apiIdentifier ID of the requesting API
     * @param registry      Current tenant registry
     * @throws APIImportExportException If an error occurs while retrieving image from the registry or
     *                                  storing in the archive directory
     */
    public static void exportAPIThumbnail(String archivePath, APIIdentifier apiIdentifier, UserRegistry registry)
            throws APIImportExportException {
        APIAndAPIProductCommonUtils.exportAPIOrAPIProductThumbnail(archivePath, apiIdentifier, registry);
    }

    /**
     * Retrieve SOAP to REST mediation logic for the exporting API and store it in the archive directory
     *
     * @param archivePath   ID of the requesting API
     * @param apiIdentifier ID of the requesting API
     * @param registry      Current tenant registry
     * @throws APIImportExportException If an error occurs while retrieving image from the registry or
     *                                  storing in the archive directory
     */
    public static void exportSOAPToRESTMediation(String archivePath, APIIdentifier apiIdentifier, UserRegistry registry)
            throws APIImportExportException {
        String soapToRestBaseUrl = "/apimgt/applicationdata/provider" + RegistryConstants.PATH_SEPARATOR +
                apiIdentifier.getProviderName() + RegistryConstants.PATH_SEPARATOR +
                apiIdentifier.getApiName() + RegistryConstants.PATH_SEPARATOR +
                apiIdentifier.getVersion() + RegistryConstants.PATH_SEPARATOR +
                "soap_to_rest";

        InputStream inputStream = null;
        OutputStream outputStream = null;
        try {
            if (registry.resourceExists(soapToRestBaseUrl)) {
                Collection inFlow = (org.wso2.carbon.registry.api.Collection) registry.get(soapToRestBaseUrl
                        + RegistryConstants.PATH_SEPARATOR + IN);
                Collection outFlow = (org.wso2.carbon.registry.api.Collection) registry.get(soapToRestBaseUrl
                        + RegistryConstants.PATH_SEPARATOR + OUT);

                CommonUtil.createDirectory(archivePath + File.separator + SOAPTOREST + File.separator + IN);
                CommonUtil.createDirectory(archivePath + File.separator + SOAPTOREST + File.separator + OUT);
                if (inFlow != null) {
                    for (String inFlowPath : inFlow.getChildren()) {
                        inputStream = registry.get(inFlowPath).getContentStream();
                        outputStream = new FileOutputStream(archivePath + File.separator + SOAPTOREST
                                + File.separator + IN +
                                inFlowPath.substring(inFlowPath.lastIndexOf(RegistryConstants.PATH_SEPARATOR)));
                        IOUtils.copy(inputStream, outputStream);
                        IOUtils.closeQuietly(inputStream);
                        IOUtils.closeQuietly(outputStream);
                    }
                }
                if (outFlow != null) {
                    for (String outFlowPath : outFlow.getChildren()) {
                        inputStream = registry.get(outFlowPath).getContentStream();
                        outputStream = new FileOutputStream(archivePath + File.separator + SOAPTOREST
                                + File.separator + OUT +
                                outFlowPath.substring(outFlowPath.lastIndexOf(RegistryConstants.PATH_SEPARATOR)));
                        IOUtils.copy(inputStream, outputStream);
                        IOUtils.closeQuietly(inputStream);
                        IOUtils.closeQuietly(outputStream);
                    }
                }
            }
        } catch (IOException e) {
            throw new APIImportExportException("I/O error while writing API SOAP to REST logic to file", e);
        } catch (RegistryException e) {
            throw new APIImportExportException("Error while retrieving SOAP to REST logic", e);
        } finally {
            IOUtils.closeQuietly(inputStream);
            IOUtils.closeQuietly(outputStream);
        }
    }

    /**
     * Retrieve documentation for the exporting API and store it in the archive directory.
     * FILE, INLINE, MARKDOWN and URL documentations are handled.
     *
     * @param archivePath   File path to the documents to be exported
     * @param apiIdentifier ID of the requesting API
     * @param registry      Current tenant registry
     * @param exportFormat  Format for export
     * @param apiProvider   API Provider
     * @throws APIImportExportException If an error occurs while retrieving documents from the
     *                                  registry or storing in the archive directory
     * @throws APIManagementException If an error occurs while retrieving document details
     */
    public static void exportAPIDocumentation(String archivePath, APIIdentifier apiIdentifier, Registry registry,
                                              ExportFormat exportFormat, APIProvider apiProvider)
            throws APIImportExportException, APIManagementException {
        APIAndAPIProductCommonUtils.exportAPIOrAPIProductDocumentation(archivePath, apiIdentifier, registry,
                exportFormat, apiProvider);
    }

    /**
     * Retrieve WSDL for the exporting API and store it in the archive directory.
     *
     * @param apiIdentifier ID of the requesting API
     * @param registry      Current tenant registry
     * @throws APIImportExportException If an error occurs while retrieving WSDL from the registry or
     *                                  storing in the archive directory
     */
    public static void exportWSDL(String archivePath, APIIdentifier apiIdentifier, Registry registry)
            throws APIImportExportException {

        String wsdlPath = APIConstants.API_WSDL_RESOURCE_LOCATION + apiIdentifier.getProviderName() + "--"
                + apiIdentifier.getApiName() + apiIdentifier.getVersion() + APIConstants.WSDL_FILE_EXTENSION;
        try {
            if (registry.resourceExists(wsdlPath)) {
                CommonUtil.createDirectory(archivePath + File.separator + "WSDL");
                Resource wsdl = registry.get(wsdlPath);
                try (InputStream wsdlStream = wsdl.getContentStream();
                     OutputStream outputStream = new FileOutputStream(archivePath + File.separator + "WSDL"
                             + File.separator + apiIdentifier.getApiName() + "-" + apiIdentifier.getVersion()
                             + APIConstants.WSDL_FILE_EXTENSION)) {
                    IOUtils.copy(wsdlStream, outputStream);
                    if (log.isDebugEnabled()) {
                        log.debug("WSDL file: " + wsdlPath + " retrieved successfully");
                    }
                }
            } else if (log.isDebugEnabled()) {
                log.debug("WSDL resource does not exists in path: " + wsdlPath + ". Skipping WSDL export.");
            }
        } catch (IOException e) {
            String errorMessage = "I/O error while writing WSDL: " + wsdlPath + " to file";
            throw new APIImportExportException(errorMessage, e);
        } catch (RegistryException e) {
            String errorMessage = "Error while retrieving WSDL: " + wsdlPath + " to file";
            throw new APIImportExportException(errorMessage, e);
        }
    }

    /**
     * Retrieve available custom sequences and API specific sequences for API export.
     *
     * @param api      exporting API
     * @param registry current tenant registry
     * @throws APIImportExportException If an error occurs while exporting sequences
     */
    public static void exportSequences(String archivePath, API api, Registry registry) throws APIImportExportException {

        Map<String, String> sequences = new HashMap<>();
        APIIdentifier apiIdentifier = api.getId();
        String seqArchivePath = archivePath.concat(File.separator + "Sequences");

        if (api.getInSequence() != null) {
            sequences.put(APIConstants.API_CUSTOM_SEQUENCE_TYPE_IN, api.getInSequence());
        }

        if (api.getOutSequence() != null) {
            sequences.put(APIConstants.API_CUSTOM_SEQUENCE_TYPE_OUT, api.getOutSequence());
        }

        if (api.getFaultSequence() != null) {
            sequences.put(APIConstants.API_CUSTOM_SEQUENCE_TYPE_FAULT, api.getFaultSequence());
        }

        if (!sequences.isEmpty()) {
            CommonUtil.createDirectory(seqArchivePath);
            for (Map.Entry<String, String> sequence : sequences.entrySet()) {
                AbstractMap.SimpleEntry<String, OMElement> sequenceDetails;
                String sequenceName = sequence.getValue();
                String direction = sequence.getKey();
                String pathToExportedSequence = seqArchivePath + File.separator + direction + "-sequence" + File.separator;
                if (sequenceName != null) {
                    sequenceDetails = getCustomSequence(sequenceName, direction, registry);
                    if (sequenceDetails == null) {
                        //If sequence doesn't exist in 'apimgt/customsequences/{in/out/fault}' directory check in API
                        //specific registry path
                        sequenceDetails = getAPISpecificSequence(api.getId(), sequenceName, direction, registry);
                        pathToExportedSequence += APIImportExportConstants.CUSTOM_TYPE + File.separator;
                    }
                    writeSequenceToFile(pathToExportedSequence, sequenceDetails, apiIdentifier);
                }
            }
        } else if (log.isDebugEnabled()) {
            log.debug("No custom sequences available for API: " + apiIdentifier.getApiName() + StringUtils.SPACE
                    + APIConstants.API_DATA_VERSION + ": " + apiIdentifier.getVersion()
                    + ". Skipping custom sequence export.");
        }
    }

    /**
     * Retrieve custom sequence details from the registry.
     *
     * @param sequenceName Name of the sequence
     * @param type         Sequence type
     * @param registry     Current tenant registry
     * @return Registry resource name of the sequence and its content
     * @throws APIImportExportException If an error occurs while retrieving registry elements
     */
    private static AbstractMap.SimpleEntry<String, OMElement> getCustomSequence(String sequenceName, String type,
                                                                                Registry registry)
            throws APIImportExportException {

        String regPath = null;
        if (APIConstants.API_CUSTOM_SEQUENCE_TYPE_IN.equals(type)) {
            regPath = APIConstants.API_CUSTOM_INSEQUENCE_LOCATION;
        } else if (APIConstants.API_CUSTOM_SEQUENCE_TYPE_OUT.equals(type)) {
            regPath = APIConstants.API_CUSTOM_OUTSEQUENCE_LOCATION;
        } else if (APIConstants.API_CUSTOM_SEQUENCE_TYPE_FAULT.equals(type)) {
            regPath = APIConstants.API_CUSTOM_FAULTSEQUENCE_LOCATION;
        }
        return getSeqDetailsFromRegistry(sequenceName, regPath, registry);
    }

    /**
     * Retrieve API Specific sequence details from the registry.
     *
     * @param sequenceName Name of the sequence
     * @param type         Sequence type
     * @param registry     Current tenant registry
     * @return Registry resource name of the sequence and its content
     * @throws APIImportExportException If an error occurs while retrieving registry elements
     */
    private static AbstractMap.SimpleEntry<String, OMElement> getAPISpecificSequence(APIIdentifier api,
                                                                                     String sequenceName, String type,
                                                                                     Registry registry)
            throws APIImportExportException {

        String regPath = APIConstants.API_ROOT_LOCATION + RegistryConstants.PATH_SEPARATOR + api.getProviderName()
                + RegistryConstants.PATH_SEPARATOR + api.getApiName() + RegistryConstants.PATH_SEPARATOR
                + api.getVersion() + RegistryConstants.PATH_SEPARATOR + type;
        return getSeqDetailsFromRegistry(sequenceName, regPath, registry);
    }

    /**
     * Retrieve sequence details from registry by given registry path.
     *
     * @param sequenceName Sequence Name
     * @param regPath      Registry path
     * @param registry     Registry
     * @return Sequence details as a simple entry
     * @throws APIImportExportException If an error occurs while retrieving sequence details from registry
     */
    private static AbstractMap.SimpleEntry<String, OMElement> getSeqDetailsFromRegistry(String sequenceName,
                                                                                        String regPath, Registry registry)
            throws APIImportExportException {

        AbstractMap.SimpleEntry<String, OMElement> sequenceDetails = null;
        Collection seqCollection;

        try {
            seqCollection = (Collection) registry.get(regPath);
            if (seqCollection != null) {
                String[] childPaths = seqCollection.getChildren();
                for (String childPath : childPaths) {
                    Resource sequence = registry.get(childPath);
                    OMElement seqElement = APIUtil.buildOMElement(sequence.getContentStream());
                    if (sequenceName.equals(seqElement.getAttributeValue(new QName("name")))) {
                        String sequenceFileName = sequenceName + APIConstants.XML_EXTENSION;
                        sequenceDetails = new AbstractMap.SimpleEntry<>(sequenceFileName, seqElement);
                        break;
                    }
                }
            }
        } catch (RegistryException e) {
            String errorMessage = "Error while retrieving sequence: " + sequenceName + " from the path: " + regPath;
            throw new APIImportExportException(errorMessage, e);
        } catch (Exception e) {
            //APIUtil.buildOMElement() throws a generic exception
            String errorMessage = "Error while reading content for sequence: " + sequenceName + " from the registry";
            throw new APIImportExportException(errorMessage, e);
        }
        return sequenceDetails;
    }

    /**
     * Store API Specific or custom sequences in the archive directory.
     *
     * @param sequenceDetails Details of the sequence
     * @param apiIdentifier   ID of the requesting API
     * @throws APIImportExportException If an error occurs while serializing XML stream or storing in
     *                                  archive directory
     */
    private static void writeSequenceToFile(String pathToExportedSequence,
                                            AbstractMap.SimpleEntry<String, OMElement> sequenceDetails,
                                            APIIdentifier apiIdentifier)
            throws APIImportExportException {

        if (sequenceDetails != null) {
            String sequenceFileName = sequenceDetails.getKey();
            OMElement sequenceConfig = sequenceDetails.getValue();
            CommonUtil.createDirectory(pathToExportedSequence);
            String exportedSequenceFile = pathToExportedSequence + sequenceFileName;
            try (OutputStream outputStream = new FileOutputStream(exportedSequenceFile)) {
                sequenceConfig.serialize(outputStream);
                if (log.isDebugEnabled()) {
                    log.debug(sequenceFileName + " of API: " + apiIdentifier.getApiName() + " retrieved successfully");
                }
            } catch (IOException e) {
                String errorMessage = "Unable to find file: " + exportedSequenceFile;
                throw new APIImportExportException(errorMessage, e);
            } catch (XMLStreamException e) {
                String errorMessage = "Error while processing XML stream ";
                throw new APIImportExportException(errorMessage, e);
            }
        } else {
            String errorMessage = "Error while writing sequence of API: " + apiIdentifier.getApiName() + " to file.";
            throw new APIImportExportException(errorMessage);
        }
    }

    /**
     * Export endpoint certificates.
     *
     * @param apiDto       APIDTO to be exported
     * @param tenantId     tenant id of the user
     * @param exportFormat Export format of file
     * @throws APIImportExportException If an error occurs while exporting endpoint certificates
     */
    public static void exportEndpointCertificates(String archivePath, APIDTO apiDto, int tenantId,
                                                  ExportFormat exportFormat) throws APIImportExportException {
        List<String> productionEndpoints;
        List<String> sandboxEndpoints;
        Set<String> uniqueEndpointURLs = new HashSet<>();
        JsonArray endpointCertificatesDetails = new JsonArray();
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String endpointConfigString = gson.toJson(apiDto.getEndpointConfig());
        String endpointCertsDirectoryPath = archivePath + File.separator
                + APIImportExportConstants.ENDPOINT_CERTIFICATES_DIRECTORY;
        CommonUtil.createDirectory(endpointCertsDirectoryPath);

        if (StringUtils.isEmpty(endpointConfigString)) {
            if (log.isDebugEnabled()) {
                log.debug("Endpoint Details are empty for API: " + apiDto.getName() + StringUtils.SPACE
                        + APIConstants.API_DATA_VERSION + ": " + apiDto.getVersion());
            }
            return;
        }
        try {
            JSONTokener tokener = new JSONTokener(endpointConfigString);
            JSONObject endpointConfig = new JSONObject(tokener);
            productionEndpoints = getEndpointURLs(endpointConfig, APIConstants.API_DATA_PRODUCTION_ENDPOINTS,
                    apiDto.getName());
            sandboxEndpoints = getEndpointURLs(endpointConfig, APIConstants.API_DATA_SANDBOX_ENDPOINTS,
                    apiDto.getName());
            uniqueEndpointURLs.addAll(productionEndpoints); // Remove duplicate and append result
            uniqueEndpointURLs.addAll(sandboxEndpoints);

            for (String url : uniqueEndpointURLs) {
                JsonArray certificateListOfUrl = getEndpointCertificateContentAndMetaData(tenantId, url,
                        endpointCertsDirectoryPath);
                endpointCertificatesDetails.addAll(certificateListOfUrl);
            }
            if (endpointCertificatesDetails.size() > 0) {
                JsonObject endpointCertificatesJsonObject = APIAndAPIProductCommonUtils.addTypeAndVersionToFile(
                        APIImportExportConstants.TYPE_ENDPOINT_CERTIFICATES, APIImportExportConstants.APIM_VERSION,
                        gson.toJsonTree(endpointCertificatesDetails));
                String certificatesJson = gson.toJson(endpointCertificatesJsonObject);
                APIAndAPIProductCommonUtils.writeToYamlOrJson(endpointCertsDirectoryPath +
                        APIImportExportConstants.ENDPOINTS_CERTIFICATE_FILE, exportFormat, certificatesJson);
            } else if (log.isDebugEnabled()) {
                log.debug("No endpoint certificates available for API: " + apiDto.getName() + StringUtils.SPACE
                        + APIConstants.API_DATA_VERSION + ": " + apiDto.getVersion() + ". Skipping certificate export.");
            }
        } catch (JSONException e) {
            String errorMsg = "Error in converting Endpoint config to JSON object in API: " + apiDto.getName();
            throw new APIImportExportException(errorMsg, e);
        } catch (IOException e) {
            String errorMessage = "Error while retrieving saving endpoint certificate details for API: "
                    + apiDto.getName() + " as YAML";
            throw new APIImportExportException(errorMessage, e);
        }
    }

    /**
     * Get endpoint url list from endpoint config.
     *
     * @param endpointConfig JSON converted endpoint config
     * @param type           end point type - production/sandbox
     * @return list of hostnames
     */
    private static List<String> getEndpointURLs(JSONObject endpointConfig, String type, String apiName) {
        List<String> urls = new ArrayList<>();
        if (endpointConfig != null) {
            try {
                Object item;
                item = endpointConfig.get(type);
                if (item instanceof JSONArray) {
                    JSONArray endpointsJSON = new JSONArray(endpointConfig.getJSONArray(type).toString());
                    for (int i = 0; i < endpointsJSON.length(); i++) {
                        try {
                            String urlValue = endpointsJSON.getJSONObject(i).get(APIConstants.API_DATA_URL).toString();
                            urls.add(urlValue);
                        } catch (JSONException ex) {
                            log.error("Endpoint URL extraction from endpoints JSON object failed in API: "
                                    + apiName, ex);
                        }
                    }
                } else if (item instanceof JSONObject) {
                    JSONObject endpointJSON = new JSONObject(endpointConfig.getJSONObject(type).toString());
                    try {
                        String urlValue = endpointJSON.get(APIConstants.API_DATA_URL).toString();
                        urls.add(urlValue);
                    } catch (JSONException ex) {
                        log.error("Endpoint URL extraction from endpoint JSON object failed in API: " + apiName, ex);
                    }
                }
            } catch (JSONException ex) {
                log.info("Endpoint type: " + type + " not found in API: " + apiName);
            }
        }
        return urls;
    }

    /**
     * Retrieve meta information of the API to export.
     * URL template information are stored in swagger.json definition while rest of the required
     * data are in api.json
     *
     * @param archivePath    Folder path to export meta information
     * @param apiDtoToReturn APIDTO to be exported
     * @param exportFormat   Export format of file
     * @param apiProvider    API Provider
     * @param apiIdentifier  API Identifier
     * @param userName       Username
     * @throws APIImportExportException If an error occurs while exporting meta information
     */
    public static void exportAPIMetaInformation(String archivePath, APIDTO apiDtoToReturn, ExportFormat exportFormat,
                                                APIProvider apiProvider, APIIdentifier apiIdentifier, String userName)
            throws APIImportExportException {

        CommonUtil.createDirectory(archivePath + File.separator + APIImportExportConstants.META_INFO_DIRECTORY);

        try {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();

            // If a web socket API is exported, it does not contain a swagger file.
            // Therefore swagger export is only required for REST, Graphql or SOAP based APIs
            String apiType = apiDtoToReturn.getType().toString();
            if (!APIConstants.APITransportType.WS.toString().equalsIgnoreCase(apiType)) {
                //For Graphql APIs, the graphql schema definition, swagger and the serialized api object are exported.
                if (StringUtils.equals(apiType, APIConstants.APITransportType.GRAPHQL.toString())) {
                    String schemaContent = apiProvider.getGraphqlSchema(apiIdentifier);
                    CommonUtil.writeFile(archivePath + APIImportExportConstants.GRAPHQL_SCHEMA_DEFINITION_LOCATION,
                            schemaContent);
                }
                String formattedSwaggerJson = RestApiPublisherUtils.retrieveSwaggerDefinition(
                        APIMappingUtil.fromDTOtoAPI(apiDtoToReturn, userName), apiProvider);
                APIAndAPIProductCommonUtils.writeToYamlOrJson(archivePath +
                        APIImportExportConstants.SWAGGER_DEFINITION_LOCATION, exportFormat, formattedSwaggerJson);

                if (log.isDebugEnabled()) {
                    log.debug("Meta information retrieved successfully for API: " + apiDtoToReturn.getName()
                            + StringUtils.SPACE + APIConstants.API_DATA_VERSION + ": " + apiDtoToReturn.getVersion());
                }
            }
            JsonObject apiJsonObject = APIAndAPIProductCommonUtils.addTypeAndVersionToFile(
                    APIImportExportConstants.TYPE_API, APIImportExportConstants.APIM_VERSION, gson.toJsonTree(apiDtoToReturn));
            String apiInJson = gson.toJson(apiJsonObject);
            APIAndAPIProductCommonUtils.writeToYamlOrJson(archivePath +
                    APIImportExportConstants.API_FILE_LOCATION, exportFormat, apiInJson);
        } catch (APIManagementException e) {
            String errorMessage = "Error while retrieving Swagger definition for API: " + apiDtoToReturn.getName()
                    + StringUtils.SPACE + APIConstants.API_DATA_VERSION + ": " + apiDtoToReturn.getVersion();
            throw new APIImportExportException(errorMessage, e);
        } catch (IOException e) {
            String errorMessage = "Error while retrieving saving as YAML for API: " + apiDtoToReturn.getName()
                    + StringUtils.SPACE + APIConstants.API_DATA_VERSION + ": " + apiDtoToReturn.getVersion();
            throw new APIImportExportException(errorMessage, e);
        }
    }

    /**
     * Get Endpoint Certificate MetaData and Certificate detail and build JSON Array.
     *
     * @param tenantId          tenant id of the user
     * @param url               url of the endpoint
     * @param certDirectoryPath directory path to export the certificates
     * @return JSON Array of certificate details
     * @throws APIImportExportException If an error occurs while retrieving endpoint certificate metadata and content
     */
    private static JsonArray getEndpointCertificateContentAndMetaData(int tenantId, String url,
                                                                      String certDirectoryPath)
            throws APIImportExportException {

        List<CertificateMetadataDTO> certificateMetadataDTOS;
        CertificateManager certificateManager = CertificateManagerImpl.getInstance();

        try {
            certificateMetadataDTOS = certificateManager.getCertificates(tenantId, null, url);
        } catch (APIManagementException e) {
            String errorMsg = "Error retrieving certificate meta data. For tenantId: " + tenantId + " hostname: "
                    + url;
            throw new APIImportExportException(errorMsg, e);
        }

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        JsonArray certificatesList = new JsonArray();
        certificateMetadataDTOS.forEach(metadataDTO -> {
            ByteArrayInputStream certificate = null;
            try {
                certificate = certificateManager.getCertificateContent(metadataDTO.getAlias());
                certificate.close();
                byte[] certificateContent = IOUtils.toByteArray(certificate);
                String certificateContentEncoded = APIConstants.BEGIN_CERTIFICATE_STRING
                        .concat(new String(Base64.encodeBase64(certificateContent))).concat("\n")
                        .concat(APIConstants.END_CERTIFICATE_STRING);
                CommonUtil.writeFile(certDirectoryPath + File.separator + metadataDTO.getAlias() + ".crt",
                        certificateContentEncoded);
                // Add the file name to the Certificate Metadata
                JsonObject modifiedCertificateMetadata = (JsonObject) gson.toJsonTree(metadataDTO);
                modifiedCertificateMetadata.addProperty(APIImportExportConstants.CERTIFICATE_FILE,
                        metadataDTO.getAlias() + ".crt");
                certificatesList.add(modifiedCertificateMetadata);
            } catch (APIManagementException e) {
                log.error("Error retrieving certificate content. For tenantId: " + tenantId + " hostname: "
                        + url + " alias: " + metadataDTO.getAlias(), e);
            } catch (IOException e) {
                log.error("Error while converting certificate content to Byte Array. For tenantId: " + tenantId
                        + " hostname: " + url + " alias: " + metadataDTO.getAlias(), e);
            } catch (APIImportExportException e) {
                log.error("Error while writing the certificate content. For tenantId: " + tenantId + " hostname: "
                        + url + " alias: " + metadataDTO.getAlias(), e);
            } finally {
                if (certificate != null) {
                    IOUtils.closeQuietly(certificate);
                }
            }
        });
        return certificatesList;
    }

    /**
     * This method used to check whether the config for exposing endpoint security password when getting API is enabled
     * or not in tenant-conf.json in registry.
     *
     * @return boolean as config enabled or not
     * @throws APIManagementException
     */
    private static boolean isExposeEndpointPasswordEnabled(String tenantDomainName)
            throws APIManagementException {
        org.json.simple.JSONObject apiTenantConfig;
        try {
            APIMRegistryServiceImpl apimRegistryService = new APIMRegistryServiceImpl();
            String content = apimRegistryService.getConfigRegistryResourceContent(tenantDomainName,
                    APIConstants.API_TENANT_CONF_LOCATION);
            if (content != null) {
                JSONParser parser = new JSONParser();
                apiTenantConfig = (org.json.simple.JSONObject) parser.parse(content);
                if (apiTenantConfig != null) {
                    Object value = apiTenantConfig.get(APIConstants.API_TENANT_CONF_EXPOSE_ENDPOINT_PASSWORD);
                    if (value != null) {
                        return Boolean.parseBoolean(value.toString());
                    }
                }
            }
        } catch (UserStoreException e) {
            String msg = "UserStoreException thrown when getting API tenant config from registry while reading " +
                    "ExposeEndpointPassword config";
            throw new APIManagementException(msg, e);
        } catch (org.wso2.carbon.registry.core.exceptions.RegistryException e) {
            String msg = "RegistryException thrown when getting API tenant config from registry while reading " +
                    "ExposeEndpointPassword config";
            throw new APIManagementException(msg, e);
        } catch (ParseException e) {
            String msg = "ParseException thrown when parsing API tenant config from registry while reading " +
                    "ExposeEndpointPassword config";
            throw new APIManagementException(msg, e);
        }
        return false;
    }

    public static File exportApi(APIProvider apiProvider, APIIdentifier apiIdentifier, APIDTO apiDtoToReturn,
                                 String userName, ExportFormat exportFormat, Boolean preserveStatus)
            throws APIManagementException {
        int tenantId = 0;
        try {
            // Create temp location for storing API data
            File exportFolder = CommonUtil.createTempDirectory(apiIdentifier);
            String exportAPIBasePath = exportFolder.toString();
            String archivePath = exportAPIBasePath.concat(File.separator + apiIdentifier.getApiName() + "-"
                    + apiIdentifier.getVersion());
            tenantId = APIUtil.getTenantId(userName);
            UserRegistry registry = ServiceReferenceHolder.getInstance().getRegistryService().
                    getGovernanceSystemRegistry(tenantId);

            CommonUtil.createDirectory(archivePath);

            ExportApiUtils.exportAPIThumbnail(archivePath, apiIdentifier, registry);
            ExportApiUtils.exportSOAPToRESTMediation(archivePath, apiIdentifier, registry);
            ExportApiUtils.exportAPIDocumentation(archivePath, apiIdentifier, registry, exportFormat, apiProvider);

            if (StringUtils.isNotEmpty(apiDtoToReturn.getWsdlUrl())) {
                ExportApiUtils.exportWSDL(archivePath, apiIdentifier, registry);
            } else if (log.isDebugEnabled()) {
                log.debug("No WSDL URL found for API: " + apiIdentifier + ". Skipping WSDL export.");
            }

            ExportApiUtils.exportSequences(archivePath, APIMappingUtil.fromDTOtoAPI(apiDtoToReturn, userName), registry);

            // Set API status to created if the status is not preserved
            if (!preserveStatus) {
                apiDtoToReturn.setLifeCycleStatus(APIConstants.CREATED);
            }

            ExportApiUtils.exportEndpointCertificates(archivePath, apiDtoToReturn, tenantId, exportFormat);
            ExportApiUtils.exportAPIMetaInformation(archivePath, apiDtoToReturn, exportFormat, apiProvider,
                    apiIdentifier, userName);

            // Export mTLS authentication related certificates
            if (apiProvider.isClientCertificateBasedAuthenticationConfigured()) {
                if (log.isDebugEnabled()) {
                    log.debug("Mutual SSL enabled. Exporting client certificates.");
                }
                ApiTypeWrapper apiTypeWrapper = new ApiTypeWrapper(APIMappingUtil.fromDTOtoAPI(apiDtoToReturn, userName));
                APIAndAPIProductCommonUtils.exportClientCertificates(archivePath, apiTypeWrapper, tenantId, apiProvider,
                        exportFormat);
            }
            CommonUtil.archiveDirectory(exportAPIBasePath);
            FileUtils.deleteQuietly(new File(exportAPIBasePath));
            return new File(exportAPIBasePath + APIConstants.ZIP_FILE_EXTENSION);
        } catch (RegistryException e) {
            String errorMessage = "Error while getting governance registry for tenant: " + tenantId;
            throw new APIManagementException(errorMessage, e);
        } catch (APIManagementException | APIImportExportException e) {
            RestApiUtil.handleInternalServerError("Error while exporting " + RestApiConstants.RESOURCE_API, e, log);
        }
        return null;
    }
}
