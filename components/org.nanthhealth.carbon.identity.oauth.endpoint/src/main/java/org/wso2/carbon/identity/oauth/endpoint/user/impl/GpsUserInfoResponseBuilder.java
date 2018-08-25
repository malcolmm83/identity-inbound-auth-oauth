package org.wso2.carbon.identity.oauth.endpoint.user.impl;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class GpsUserInfoResponseBuilder extends UserInfoJWTResponse {

    private static final Log log = LogFactory.getLog(GpsUserInfoResponseBuilder.class);

    private static final Map<String, String[]> role2permissions;
    static
    {
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
    protected String buildResponse(OAuth2TokenValidationResponseDTO tokenResponse,
                                   String spTenantDomain,
                                   Map<String, Object> filteredUserClaims) throws UserInfoEndpointException {

        String[] scopes = tokenResponse.getScope();
        if (Arrays.asList(scopes).contains("gps")) {
            log.info("access token has gps scope");
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
            }
            catch (Exception ex) {
                log.info("can't find employeenumber", ex);
            }

            JSONObject organizationContext = new JSONObject();
            String organization = (String) filteredUserClaims.get("organization");
            if (organization != null) {
                organizationContext.put("read", "https://navinet.nanthealth.io/identifier/officenid|" + organization);
                organizationContext.put("write", "https://navinet.nanthealth.io/identifier/officenid|" + organization);
            }
            else {
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
        }

        return super.buildResponse(tokenResponse, spTenantDomain, filteredUserClaims);
    }

}
