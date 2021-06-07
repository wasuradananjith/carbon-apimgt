package org.wso2.carbon.apimgt.rest.api.admin.v1.impl;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import feign.Feign;
import feign.gson.GsonDecoder;
import feign.gson.GsonEncoder;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.wso2.carbon.apimgt.api.APIAdmin;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.ExceptionCodes;
import org.wso2.carbon.apimgt.api.dto.KeyManagerConfigurationDTO;
import org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration;
import org.wso2.carbon.apimgt.impl.APIAdminImpl;
import org.wso2.carbon.apimgt.impl.kmclient.ApacheFeignHttpClient;
import org.wso2.carbon.apimgt.impl.kmclient.KMClientErrorDecoder;
import org.wso2.carbon.apimgt.impl.kmclient.model.OpenIDConnectDiscoveryClient;
import org.wso2.carbon.apimgt.impl.kmclient.model.OpenIdConnectConfiguration;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.rest.api.admin.v1.KeyManagersApiService;
import org.wso2.carbon.apimgt.rest.api.admin.v1.dto.ClaimMappingEntryDTO;
import org.wso2.carbon.apimgt.rest.api.admin.v1.dto.KeyManagerCertificatesDTO;
import org.wso2.carbon.apimgt.rest.api.admin.v1.dto.KeyManagerDTO;
import org.wso2.carbon.apimgt.rest.api.admin.v1.dto.KeyManagerListDTO;
import org.wso2.carbon.apimgt.rest.api.admin.v1.dto.KeyManagerWellKnownResponseDTO;
import org.wso2.carbon.apimgt.rest.api.admin.v1.utils.mappings.KeyManagerMappingUtil;
import org.wso2.carbon.apimgt.rest.api.common.RestApiConstants;
import org.wso2.carbon.apimgt.rest.api.util.utils.RestApiUtil;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.openidconnect.model.Constants;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import javax.ws.rs.core.Response;

public class KeyManagersApiServiceImpl implements KeyManagersApiService {

    private static final Log log = LogFactory.getLog(KeyManagersApiServiceImpl.class);

    @Override
    public Response keyManagersDiscoverPost(String url, String type, MessageContext messageContext)
            throws APIManagementException {
        if (StringUtils.isNotEmpty(url)) {
            Gson gson = new GsonBuilder().serializeNulls().create();
            OpenIDConnectDiscoveryClient openIDConnectDiscoveryClient =
                    Feign.builder().client(new ApacheFeignHttpClient(APIUtil.getHttpClient(url)))
                            .encoder(new GsonEncoder(gson)).decoder(new GsonDecoder(gson))
                            .errorDecoder(new KMClientErrorDecoder())
                            .target(OpenIDConnectDiscoveryClient.class, url);
            OpenIdConnectConfiguration openIdConnectConfiguration =
                    openIDConnectDiscoveryClient.getOpenIdConnectConfiguration();
            if (openIdConnectConfiguration != null) {
                KeyManagerWellKnownResponseDTO keyManagerWellKnownResponseDTO = KeyManagerMappingUtil
                        .fromOpenIdConnectConfigurationToKeyManagerConfiguration(openIdConnectConfiguration);
                keyManagerWellKnownResponseDTO.getValue().setWellKnownEndpoint(url);
                keyManagerWellKnownResponseDTO.getValue().setType(type);
                return Response.ok().entity(keyManagerWellKnownResponseDTO).build();
            }

        }
        return Response.ok(new KeyManagerWellKnownResponseDTO()).build();
    }

    public Response keyManagersGet(MessageContext messageContext) throws APIManagementException {

        String organization = RestApiUtil.getOrganization(messageContext);
        APIAdmin apiAdmin = new APIAdminImpl();
        List<KeyManagerConfigurationDTO> keyManagerConfigurationsByOrganization =
                apiAdmin.getKeyManagerConfigurationsByTenant(organization);
        for (KeyManagerConfigurationDTO keyManagerConfigurationDTO: keyManagerConfigurationsByOrganization) {
            if (StringUtils.equals(KeyManagerConfiguration.TokenType.EXCHANGED.toString(),
                    keyManagerConfigurationDTO.getTokenType())) {
                try {
                    if (keyManagerConfigurationDTO.getExternalReferenceId() != null) {
                        IdentityProvider identityProvider = IdentityProviderManager.getInstance()
                                .getIdPByResourceId(keyManagerConfigurationDTO.getExternalReferenceId(),
                                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, Boolean.FALSE);
                        // Only two parameters that are common to IdentityProvider object and the KeyManagerInfoDTO (that
                        // will be used in KeyManagerMappingUtil.toKeyManagerListDTO) are the description and the enabled.
                        keyManagerConfigurationDTO.setDescription(identityProvider.getIdentityProviderDescription());
                        keyManagerConfigurationDTO.setEnabled(identityProvider.isEnable());
                    }
                } catch (IdentityProviderManagementException e) {
                    throw new APIManagementException("IdP retrieval failed.", ExceptionCodes.IDP_RETRIEVAL_FAILED);
                }
            }
        }
        KeyManagerListDTO keyManagerListDTO =
                KeyManagerMappingUtil.toKeyManagerListDTO(keyManagerConfigurationsByOrganization);
        return Response.ok().entity(keyManagerListDTO).build();
    }

    public Response keyManagersKeyManagerIdDelete(String keyManagerId, MessageContext messageContext)
            throws APIManagementException {

        String organization = RestApiUtil.getOrganization(messageContext);

        APIAdmin apiAdmin = new APIAdminImpl();
        KeyManagerConfigurationDTO keyManagerConfigurationDTO =
                apiAdmin.getKeyManagerConfigurationById(organization, keyManagerId);
        if (StringUtils.equals(KeyManagerConfiguration.TokenType.EXCHANGED.toString(),
                keyManagerConfigurationDTO.getTokenType())) {
            try {
                if (keyManagerConfigurationDTO.getExternalReferenceId() != null) {
                    IdentityProviderManager.getInstance()
                            .deleteIdPByResourceId(keyManagerConfigurationDTO.getExternalReferenceId(),
                                    MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                }
            } catch (IdentityProviderManagementException e) {
                throw new APIManagementException("IdP deletion failed.", ExceptionCodes.IDP_DELETION_FAILED);
            }
        }
        apiAdmin.deleteKeyManagerConfigurationById(organization, keyManagerId);

        return Response.ok().build();
    }

    public Response keyManagersKeyManagerIdGet(String keyManagerId, MessageContext messageContext)
            throws APIManagementException {

        String organization = RestApiUtil.getOrganization(messageContext);
        APIAdmin apiAdmin = new APIAdminImpl();
        KeyManagerConfigurationDTO keyManagerConfigurationDTO =
                apiAdmin.getKeyManagerConfigurationById(organization, keyManagerId);
        if (keyManagerConfigurationDTO != null) {
            KeyManagerDTO keyManagerDTO = KeyManagerMappingUtil.toKeyManagerDTO(keyManagerConfigurationDTO);
            if (StringUtils.equals(KeyManagerConfiguration.TokenType.EXCHANGED.toString(),
                    keyManagerConfigurationDTO.getTokenType())) {
                try {
                    if (keyManagerConfigurationDTO.getExternalReferenceId() != null) {
                        IdentityProvider identityProvider = IdentityProviderManager.getInstance()
                                .getIdPByResourceId(keyManagerConfigurationDTO.getExternalReferenceId(),
                                        MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, Boolean.FALSE);
                        mergeIdpWithKeyManagerConfiguration(identityProvider, keyManagerDTO);
                    }
                } catch (IdentityProviderManagementException e) {
                    throw new APIManagementException("IdP retrieval failed.", ExceptionCodes.IDP_RETRIEVAL_FAILED);
                }
            }
            return Response.ok(keyManagerDTO).build();
        }
        RestApiUtil.handleResourceNotFoundError(RestApiConstants.RESOURCE_KEY_MANAGER, keyManagerId, log);
        return null;
    }

    public Response keyManagersKeyManagerIdPut(String keyManagerId, KeyManagerDTO body, MessageContext messageContext)
            throws APIManagementException {

        String organization = RestApiUtil.getOrganization(messageContext);
        APIAdmin apiAdmin = new APIAdminImpl();
        try {
            KeyManagerConfigurationDTO keyManagerConfigurationDTO =
                    KeyManagerMappingUtil.toKeyManagerConfigurationDTO(organization, body);
            keyManagerConfigurationDTO.setUuid(keyManagerId);
            KeyManagerConfigurationDTO oldKeyManagerConfigurationDTO =
                    apiAdmin.getKeyManagerConfigurationById(organization, keyManagerId);
            if (oldKeyManagerConfigurationDTO == null) {
                RestApiUtil.handleResourceNotFoundError(RestApiConstants.RESOURCE_KEY_MANAGER, keyManagerId, log);
            } else {
                if (!oldKeyManagerConfigurationDTO.getName().equals(keyManagerConfigurationDTO.getName())) {
                    RestApiUtil.handleBadRequest("Key Manager name couldn't able to change", log);
                }
                if (StringUtils.equals(KeyManagerConfiguration.TokenType.EXCHANGED.toString(),
                        body.getTokenType().toString())) {
                    IdentityProvider identityProvider = IdentityProviderManager.getInstance()
                            .updateIdPByResourceId(oldKeyManagerConfigurationDTO.getExternalReferenceId(),
                                    createIdp(keyManagerConfigurationDTO, body, organization),
                                    MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                    keyManagerConfigurationDTO.setExternalReferenceId(identityProvider.getResourceId());
                }
                KeyManagerConfigurationDTO retrievedKeyManagerConfigurationDTO =
                        apiAdmin.updateKeyManagerConfiguration(keyManagerConfigurationDTO);
                return Response.ok(KeyManagerMappingUtil.toKeyManagerDTO(retrievedKeyManagerConfigurationDTO)).build();
            }
        } catch (APIManagementException e) {
            String error =
                    "Error while Retrieving Key Manager configuration for " + keyManagerId + " in organization " +
                            organization;
            RestApiUtil.handleInternalServerError(error, e, log);
        } catch (IdentityProviderManagementException e) {
            throw new APIManagementException("IdP adding failed.", ExceptionCodes.IDP_ADDING_FAILED);
        }
        return null;
    }

    public Response keyManagersPost(KeyManagerDTO body, MessageContext messageContext) throws APIManagementException {

        String organization = RestApiUtil.getOrganization(messageContext);
        APIAdmin apiAdmin = new APIAdminImpl();
        try {
            KeyManagerConfigurationDTO keyManagerConfigurationDTO =
                    KeyManagerMappingUtil.toKeyManagerConfigurationDTO(organization, body);
            if (StringUtils
                    .equals(KeyManagerConfiguration.TokenType.EXCHANGED.toString(), body.getTokenType().toString())) {
                keyManagerConfigurationDTO.setUuid(UUID.randomUUID().toString());
                IdentityProvider identityProvider = IdentityProviderManager.getInstance()
                        .addIdPWithResourceId(createIdp(keyManagerConfigurationDTO, body, organization),
                                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                keyManagerConfigurationDTO.setExternalReferenceId(identityProvider.getResourceId());
            }
            KeyManagerConfigurationDTO createdKeyManagerConfiguration =
                    apiAdmin.addKeyManagerConfiguration(keyManagerConfigurationDTO);
            URI location = new URI(RestApiConstants.KEY_MANAGERS + "/" + createdKeyManagerConfiguration.getUuid());
            return Response.created(location)
                    .entity(KeyManagerMappingUtil.toKeyManagerDTO(createdKeyManagerConfiguration)).build();
        } catch (URISyntaxException e) {
            String error = "Error while Creating Key Manager configuration in organization " + organization;
            RestApiUtil.handleInternalServerError(error, e, log);
        } catch (IdentityProviderManagementException e) {
            throw new APIManagementException("IdP adding failed.", ExceptionCodes.IDP_ADDING_FAILED);
        }
        return null;
    }

    private IdentityProvider createIdp(KeyManagerConfigurationDTO keyManagerConfigurationDTO,
            KeyManagerDTO keyManagerDTO, String organization) {

        IdentityProvider identityProvider = new IdentityProvider();
        String idpName = sanitizeName(
                keyManagerConfigurationDTO.getName().substring(0, 5) + "_" + organization.substring(0, 5) + "_"
                        + keyManagerConfigurationDTO.getUuid().substring(0, 5));
        identityProvider.setIdentityProviderName(idpName);
        identityProvider.setDisplayName(keyManagerConfigurationDTO.getDisplayName());
        identityProvider.setPrimary(Boolean.FALSE);
        identityProvider.setIdentityProviderDescription(keyManagerConfigurationDTO.getDescription());
        identityProvider.setAlias(keyManagerConfigurationDTO.getAlias());
        KeyManagerCertificatesDTO keyManagerCertificatesDTO = keyManagerDTO.getCertificates();

        if (keyManagerCertificatesDTO != null) {
            if (keyManagerCertificatesDTO.getType().equals(KeyManagerCertificatesDTO.TypeEnum.JWKS)) {
                String idpJWKSUri = keyManagerCertificatesDTO.getValue();
                List<IdentityProviderProperty> idpProperties = new ArrayList<>();
                if (StringUtils.isNotBlank(idpJWKSUri)) {
                    IdentityProviderProperty jwksProperty = new IdentityProviderProperty();
                    jwksProperty.setName(Constants.JWKS_URI);
                    jwksProperty.setValue(idpJWKSUri);
                    idpProperties.add(jwksProperty);
                }
                identityProvider.setIdpProperties(idpProperties.toArray(new IdentityProviderProperty[0]));
            } else if (keyManagerCertificatesDTO.getType().equals(KeyManagerCertificatesDTO.TypeEnum.PEM)) {
                identityProvider.setCertificate(StringUtils.join(keyManagerCertificatesDTO.getValue(), ""));
            }
        }
        identityProvider.setEnable(keyManagerConfigurationDTO.isEnabled());
        updateClaims(identityProvider, keyManagerDTO.getClaimMapping());
        return identityProvider;
    }

    private void updateClaims(IdentityProvider idp, List<ClaimMappingEntryDTO> claims) {
        if (claims != null) {
            ClaimConfig claimConfig = new ClaimConfig();
            List<ClaimMapping> claimMappings = new ArrayList<>();
            List<org.wso2.carbon.identity.application.common.model.Claim> idpClaims = new ArrayList<>();

            if (CollectionUtils.isNotEmpty(claims)) {
                claimConfig.setLocalClaimDialect(false);

                for (ClaimMappingEntryDTO claimMappingEntry : claims) {
                    String idpClaimUri = claimMappingEntry.getRemoteClaim();
                    String localClaimUri = claimMappingEntry.getLocalClaim();

                    ClaimMapping internalMapping = new ClaimMapping();
                    org.wso2.carbon.identity.application.common.model.Claim remoteClaim =
                            new org.wso2.carbon.identity.application.common.model.Claim();
                    remoteClaim.setClaimUri(idpClaimUri);

                    org.wso2.carbon.identity.application.common.model.Claim localClaim =
                            new org.wso2.carbon.identity.application.common.model.Claim();
                    localClaim.setClaimUri(localClaimUri);

                    internalMapping.setRemoteClaim(remoteClaim);
                    internalMapping.setLocalClaim(localClaim);
                    claimMappings.add(internalMapping);
                    idpClaims.add(remoteClaim);
                }
            } else {
                claimConfig.setLocalClaimDialect(true);
            }

            claimConfig.setClaimMappings(claimMappings.toArray(new ClaimMapping[0]));
            claimConfig.setIdpClaims(idpClaims.toArray(new org.wso2.carbon.identity.application.common.model.Claim[0]));
            idp.setClaimConfig(claimConfig);
        }
    }

    private void mergeIdpWithKeyManagerConfiguration(IdentityProvider identityProvider, KeyManagerDTO keyManagerDTO) {
        keyManagerDTO.setDisplayName(identityProvider.getDisplayName());
        keyManagerDTO.setDescription(identityProvider.getIdentityProviderDescription());

        IdentityProviderProperty identityProviderProperty[] = identityProvider.getIdpProperties();
        KeyManagerCertificatesDTO keyManagerCertificatesDTO = new KeyManagerCertificatesDTO();
        if (identityProviderProperty.length > 0) {
            keyManagerCertificatesDTO.setType(KeyManagerCertificatesDTO.TypeEnum.JWKS);
            keyManagerCertificatesDTO.setValue(identityProviderProperty[0].getValue());
            keyManagerDTO.setCertificates(keyManagerCertificatesDTO);
        } else if (StringUtils.isNotBlank(identityProvider.getCertificate())) {
            keyManagerCertificatesDTO.setType(KeyManagerCertificatesDTO.TypeEnum.PEM);
            keyManagerCertificatesDTO.setValue(identityProvider.getCertificate());
            keyManagerDTO.setCertificates(keyManagerCertificatesDTO);
        }

        keyManagerDTO.setEnabled(identityProvider.isEnable());
        keyManagerDTO.setAlias(identityProvider.getAlias());

        ClaimConfig claimConfig = identityProvider.getClaimConfig();
        org.wso2.carbon.identity.application.common.model.Claim[] idpClaims = claimConfig.getIdpClaims();
        List<ClaimMappingEntryDTO> claimMappingEntryDTOList = new ArrayList<>();
        for (ClaimMapping claimMapping: claimConfig.getClaimMappings()) {
            ClaimMappingEntryDTO claimMappingEntryDTO = new ClaimMappingEntryDTO();
            claimMappingEntryDTO.setLocalClaim(claimMapping.getLocalClaim().getClaimUri());
            claimMappingEntryDTO.setRemoteClaim(claimMapping.getRemoteClaim().getClaimUri());
            claimMappingEntryDTOList.add(claimMappingEntryDTO);
        }
        keyManagerDTO.setClaimMapping(claimMappingEntryDTOList);
    }

    public String sanitizeName(String inputName) {
        return inputName.replaceAll("[^a-zA-Z0-9-_\\.]", "");
    }
}
