/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.endpoint.user.impl;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.endpoint.util.ClaimUtil;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuer;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.AbstractUserInfoResponseBuilder;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.apache.commons.lang.StringUtils.isNotBlank;

/**
 * Builds user info response as a JWT according to http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
 */
public class GpsUserInfoResponseBuilder extends AbstractUserInfoResponseBuilder {

    private static final Log log = LogFactory.getLog(GpsUserInfoResponseBuilder.class);
    private static final JWSAlgorithm DEFAULT_SIGNATURE_ALGORITHM = new JWSAlgorithm(JWSAlgorithm.NONE.getName());


    private static final Map<String, String[]> role2permissions;
    static
    {
        log.warn("initializing GpsUserInfoResponseBuilder");
        role2permissions = new HashMap<String, String[]>();
        role2permissions.put("GpsOrdering", new String[]{
                "GpsOrdering",
                "ProcedureRequest.Read.Completed",
                "ProcedureRequest.Read.Draft",
                "ProcedureRequest.Read.Active",
                "ProcedureRequest.Read.Suspended",
                "ProcedureRequest.Read.Entered-In-Error",
                "ProcedureRequest.Read.Cancelled",
                "ProcedureRequest.Write.Active",
                "ProcedureRequest.Write.Draft",
                "ProcedureRequest.Write.Draft.Active",
                "ProcedureRequest.Write.Draft.Entered-In-Error",
                "Organization.Read",
                "Organization.Write",
                "Practitioner.Read",
                "Practitioner.Write",
                "PractitionerRole.Read",
                "PractitionerRole.Write",
                "Patient.Read",
                "Patient.Write",
                "DiagnosticReport.Read",
                "DiagnosticReport.Write",
                "Coverage.Read",
                "Coverage.Write",
                "Specimen.Read",
                "Specimen.Write",
                "Condition.Read",
                "Condition.Write",
                "ReferralRequest.Read",
                "ReferralRequest.Write",
                "Binary.Read",
                "Binary.Write",
                "Basic.Read",
                "Basic.Write",
                "CodeSystem.Read",
                "ValueSet.Read",
                "Provenance.Read"});
    }


    @Override
    protected Map<String, Object> retrieveUserClaims(OAuth2TokenValidationResponseDTO tokenValidationResponse)
            throws UserInfoEndpointException {
        return ClaimUtil.getUserClaimsUsingTokenResponse(tokenValidationResponse);
    }

    protected Map<String, Object> addGpsClaims(OAuth2TokenValidationResponseDTO tokenResponse,
                                               String spTenantDomain,
                                               Map<String, Object> filteredUserClaims) throws UserInfoEndpointException {
        log.warn("GpsUserInfoResponseBuilder.addGpsClaims called");


        JSONObject gpsSubId = new JSONObject();

        String roleString = (String) filteredUserClaims.getOrDefault("groups", "");
        ArrayList<String> roles = new ArrayList<String>(Arrays.asList(roleString.split(",")));
        for (String role : roles) {
            String[] perms = role2permissions.getOrDefault(role, new String[0]);
            log.info("role: " + role + " permissions: " + perms);
            gpsSubId.put("permissions", perms);
            log.info("gpsSubId: " + gpsSubId.toString(2));
            break;
        }

        try {
            String employeeNumberString = (String) filteredUserClaims.get("employeenumber");
            if (employeeNumberString != null) {
                long employeeNumber = Long.parseLong(employeeNumberString.trim());
                gpsSubId.put("id", employeeNumber);
                log.info("gpsSubId: " + gpsSubId.toString(2));
            }
        } catch (Exception ex) {
            log.info("can't find employeenumber", ex);
        }

        JSONObject organizationContext = new JSONObject();
        String organization = (String) filteredUserClaims.get("organization");
        if (organization != null) {
            organizationContext.put("read", "https://navinet.nanthealth.io/identifier/officenid|" + organization);
            organizationContext.put("write", "https://navinet.nanthealth.io/identifier/officenid|" + organization);
        } else {
            organizationContext.put("read", "*");
            organizationContext.put("write", "*");
        }
        log.info("organizationContext: " + organizationContext.toString(2));
        gpsSubId.put("organizationContext", organizationContext);
        log.info("gpsSubId: " + gpsSubId.toString(2));

        try {
            if (organization != null) {
                long officeNid = Long.parseLong(organization.trim());
                gpsSubId.put("officeNid", officeNid);
                log.info("gpsSubId: " + gpsSubId.toString(2));
            }
        } catch (Exception ex) {
            log.info("can't find officeNid", ex);
        }

        JSONArray subjectIdentities = new JSONArray();
        subjectIdentities.put(gpsSubId);
        log.info("subjectIdentities: " + subjectIdentities.toString(2));
        filteredUserClaims.put("subject-identities", subjectIdentities);
        log.info("filteredUserClaims: " + filteredUserClaims.toString());

        return filteredUserClaims;
    }

    @Override
    protected String buildResponse(OAuth2TokenValidationResponseDTO tokenResponse,
                                   String spTenantDomain,
                                   Map<String, Object> filteredUserClaims) throws UserInfoEndpointException {
        log.warn("GpsUserInfoResponseBuilder.buildResponse called");

        String[] scopes = tokenResponse.getScope();
        log.warn("scopes: " + scopes);
        if (Arrays.asList(scopes).contains("gps")) {
            log.info("access token has gps scope");
            filteredUserClaims = addGpsClaims(tokenResponse, spTenantDomain, filteredUserClaims);
        }

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        for (Map.Entry<String, Object> entry : filteredUserClaims.entrySet()) {
            jwtClaimsSetBuilder.claim(entry.getKey(), entry.getValue());
        }
        return buildJWTResponse(tokenResponse, spTenantDomain, jwtClaimsSetBuilder.build());
    }

    private String buildJWTResponse(OAuth2TokenValidationResponseDTO tokenResponse,
                                    String spTenantDomain,
                                    JWTClaimsSet jwtClaimsSet) throws UserInfoEndpointException {
        JWSAlgorithm signatureAlgorithm = getJWTSignatureAlgorithm();
        if (JWSAlgorithm.NONE.equals(signatureAlgorithm)) {
            if (log.isDebugEnabled()) {
                log.debug("User Info JWT Signature algorithm is not defined. Returning unsigned JWT.");
            }
            return new PlainJWT(jwtClaimsSet).serialize();
        }

        // Tenant domain to which the signing key belongs to.
        String signingTenantDomain = getSigningTenantDomain(tokenResponse, spTenantDomain);
        try {
            return OAuth2Util.signJWT(jwtClaimsSet, signatureAlgorithm, signingTenantDomain).serialize();
        } catch (IdentityOAuth2Exception e) {
            throw new UserInfoEndpointException("Error occurred while signing JWT", e);
        }
    }

    private JWSAlgorithm getJWTSignatureAlgorithm() throws UserInfoEndpointException {
        JWSAlgorithm signatureAlgorithm = DEFAULT_SIGNATURE_ALGORITHM;
        String sigAlg = OAuthServerConfiguration.getInstance().getUserInfoJWTSignatureAlgorithm();
        if (isNotBlank(sigAlg)) {
            try {
                signatureAlgorithm = OAuth2Util.mapSignatureAlgorithmForJWSAlgorithm(sigAlg);
            } catch (IdentityOAuth2Exception e) {
                throw new UserInfoEndpointException("Provided signature algorithm : " + sigAlg + " is not supported.", e);
            }
        }
        return signatureAlgorithm;
    }

    private String getSigningTenantDomain(OAuth2TokenValidationResponseDTO tokenResponse,
                                          String spTenantDomain) throws UserInfoEndpointException {
        boolean isJWTSignedWithSPKey = OAuthServerConfiguration.getInstance().isJWTSignedWithSPKey();
        String signingTenantDomain;
        if (isJWTSignedWithSPKey) {
            signingTenantDomain = spTenantDomain;
        } else {
            AccessTokenDO accessTokenDO = getAccessTokenDO(tokenResponse.getAuthorizationContextToken().getTokenString());
            signingTenantDomain = accessTokenDO.getAuthzUser().getTenantDomain();
        }
        return signingTenantDomain;
    }

    private AccessTokenDO getAccessTokenDO(String accessToken) throws UserInfoEndpointException {
        AccessTokenDO accessTokenDO;
        try {
            OauthTokenIssuer tokenIssuer = OAuth2Util.getTokenIssuer(accessToken);
            String tokenIdentifier = null;
            try {
                tokenIdentifier = tokenIssuer.getAccessTokenHash(accessToken);
            } catch (OAuthSystemException e) {
                log.error("Error while getting token identifier", e);
            }
            accessTokenDO = OAuth2Util.getAccessTokenDOfromTokenIdentifier(tokenIdentifier);
        } catch (IdentityOAuth2Exception e) {
            throw new UserInfoEndpointException("Error occurred while signing JWT", e);
        }

        if (accessTokenDO == null) {
            // this means the token is not active so we can't proceed further
            throw new UserInfoEndpointException(OAuthError.ResourceResponse.INVALID_TOKEN, "Invalid Access Token.");
        }
        return accessTokenDO;
    }
}
