/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.adapters;

import java.util.Collections;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.spi.AuthChallenge;
import org.keycloak.adapters.spi.AuthOutcome;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.common.enums.SslRequired;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public abstract class RequestAuthenticator {
    protected static Logger log = Logger.getLogger(RequestAuthenticator.class);
    protected HttpFacade facade;
    protected AuthChallenge challenge;

    protected KeycloakDeployment deployment;
    protected AdapterTokenStore tokenStore;
    protected int sslRedirectPort;

    public RequestAuthenticator(HttpFacade facade, KeycloakDeployment deployment, AdapterTokenStore tokenStore, int sslRedirectPort) {
        System.out.println("Going through tomcat request authenticator child class of RequestAuthenticator");
        this.facade = facade;
        this.deployment = deployment;
        this.tokenStore = tokenStore;
        this.sslRedirectPort = sslRedirectPort;
    }

    public RequestAuthenticator(HttpFacade facade, KeycloakDeployment deployment) {
        this.facade = facade;
        this.deployment = deployment;
    }

    public AuthChallenge getChallenge() {
        return challenge;
    }

    public AuthOutcome authenticate() {
        System.out.println("RequestAuthenticator line 59");
        if (log.isTraceEnabled()) {
            log.trace("--> authenticate()");
        }

        BearerTokenRequestAuthenticator bearer = createBearerTokenAuthenticator();
        if (log.isTraceEnabled()) {
            log.trace("try bearer");
        }

        AuthOutcome outcome = bearer.authenticate(facade);
        if (outcome == AuthOutcome.FAILED) {
            System.out.println("RequestAuthenticator line 71");
            challenge = bearer.getChallenge();
            log.debug("Bearer FAILED");
            return AuthOutcome.FAILED;
        } else if (outcome == AuthOutcome.AUTHENTICATED) {
            System.out.println("RequestAuthenticator line 76");
            if (verifySSL()) {
                System.out.println("Line 78 RequestAuthenticator - AuthOutcome.FAILED");
                return AuthOutcome.FAILED;
            }
            completeAuthentication(bearer, "KEYCLOAK");
            log.debug("Bearer AUTHENTICATED");
            return AuthOutcome.AUTHENTICATED;
        }

        QueryParamterTokenRequestAuthenticator queryParamAuth = createQueryParamterTokenRequestAuthenticator();
        if (log.isTraceEnabled()) {
            log.trace("try query paramter auth");
        }

        outcome = queryParamAuth.authenticate(facade);
        if (outcome == AuthOutcome.FAILED) {
            System.out.println("RequestAuthenticator line 90");
            challenge = queryParamAuth.getChallenge();
            log.debug("QueryParamAuth auth FAILED");
            return AuthOutcome.FAILED;
        } else if (outcome == AuthOutcome.AUTHENTICATED) {
            System.out.println("RequestAuthenticator line 95");
            if (verifySSL()) return AuthOutcome.FAILED;
            log.debug("QueryParamAuth AUTHENTICATED");
            completeAuthentication(queryParamAuth, "KEYCLOAK");
            return AuthOutcome.AUTHENTICATED;
        }

        if (deployment.isEnableBasicAuth()) {
            System.out.println("RequestAuthenticator line 104");
            BasicAuthRequestAuthenticator basicAuth = createBasicAuthAuthenticator();
            if (log.isTraceEnabled()) {
                log.trace("try basic auth");
            }

            outcome = basicAuth.authenticate(facade);
            if (outcome == AuthOutcome.FAILED) {
                System.out.println("RequestAuthenticator line 111");
                challenge = basicAuth.getChallenge();
                log.debug("BasicAuth FAILED");
                return AuthOutcome.FAILED;
            } else if (outcome == AuthOutcome.AUTHENTICATED) {
                System.out.println("RequestAuthenticator line 116");
                if (verifySSL()) return AuthOutcome.FAILED;
                log.debug("BasicAuth AUTHENTICATED");
                completeAuthentication(basicAuth, "BASIC");
                return AuthOutcome.AUTHENTICATED;
            }
        }

        if (deployment.isBearerOnly()) {
            System.out.println("RequestAuthenticator line 125");
            challenge = bearer.getChallenge();
            log.debug("NOT_ATTEMPTED: bearer only");
            return AuthOutcome.NOT_ATTEMPTED;
        }

        if (isAutodetectedBearerOnly(facade.getRequest())) {
            System.out.println("RequestAuthenticator line 132");
            challenge = bearer.getChallenge();
            log.debug("NOT_ATTEMPTED: Treating as bearer only");
            return AuthOutcome.NOT_ATTEMPTED;
        }

        if (log.isTraceEnabled()) {
            System.out.println("try oauth");
        }

        if (tokenStore.isCached(this)) {
            System.out.println("RequestAuthenticator line 143");
            if (verifySSL()){
                System.out.println("Line 145 - should be last here then auth outcome is authenticated");
                return AuthOutcome.FAILED;
            }
            System.out.println("AUTHENTICATED: was cached");
            return AuthOutcome.AUTHENTICATED;
        }
        System.out.println("RequestAuthenticator line 148");
        OAuthRequestAuthenticator oauth = createOAuthAuthenticator();
        outcome = oauth.authenticate();
        if (outcome == AuthOutcome.FAILED) {
            System.out.println("RequestAuthenticator line 152");
            challenge = oauth.getChallenge();
            return AuthOutcome.FAILED;
        } else if (outcome == AuthOutcome.NOT_ATTEMPTED) {
            System.out.println("RequestAuthenticator line 156");
            challenge = oauth.getChallenge();
            return AuthOutcome.NOT_ATTEMPTED;

        }

        if (verifySSL()){
            System.out.println("line 166 outcome failed");
            return AuthOutcome.FAILED;
        }
        System.out.println("line169 completeAuthentication");
        completeAuthentication(oauth);

        // redirect to strip out access code and state query parameters
        facade.getResponse().setHeader("Location", oauth.getStrippedOauthParametersRequestUri());
        facade.getResponse().setStatus(302);
        facade.getResponse().end();

        System.out.println("Authenticated line 177 RequestAuthenticator");
        return AuthOutcome.AUTHENTICATED;
    }

    protected boolean verifySSL() {
        System.out.println("VerifySSL");
        if (!facade.getRequest().isSecure() && deployment.getSslRequired().isRequired(facade.getRequest().getRemoteAddr())) {
            System.out.println("RequestAuthenticator line 177");
            System.out.printf("SSL is required to authenticate. Remote address %s is secure: %s, SSL required for: %s",facade.getRequest().getRemoteAddr(), facade.getRequest().isSecure(), deployment.getSslRequired().name());
            return true;
        }
        return false;
    }

    protected boolean isAutodetectedBearerOnly(HttpFacade.Request request) {
        System.out.println("RequestAuthenticator line 189");
        if (!deployment.isAutodetectBearerOnly()) return false;

        String headerValue = facade.getRequest().getHeader("X-Requested-With");
        if (headerValue != null && headerValue.equalsIgnoreCase("XMLHttpRequest")) {
            System.out.println("RequestAuthenticator line 191");
            return true;
        }

        headerValue = facade.getRequest().getHeader("Faces-Request");
        if (headerValue != null && headerValue.startsWith("partial/")) {
            return true;
        }

        headerValue = facade.getRequest().getHeader("SOAPAction");
        if (headerValue != null) {
            return true;
        }

        List<String> accepts = facade.getRequest().getHeaders("Accept");
        if (accepts == null) accepts = Collections.emptyList();

        for (String accept : accepts) {
            if (accept.contains("text/html") || accept.contains("text/*") || accept.contains("*/*")) {
                return false;
            }
        }

        return true;
    }

    protected abstract OAuthRequestAuthenticator createOAuthAuthenticator();

    protected BearerTokenRequestAuthenticator createBearerTokenAuthenticator() {
        return new BearerTokenRequestAuthenticator(deployment);
    }

    protected BasicAuthRequestAuthenticator createBasicAuthAuthenticator() {
        return new BasicAuthRequestAuthenticator(deployment);
    }

    protected QueryParamterTokenRequestAuthenticator createQueryParamterTokenRequestAuthenticator() {
        return new QueryParamterTokenRequestAuthenticator(deployment);
    }

    protected void completeAuthentication(OAuthRequestAuthenticator oauth) {
        System.out.println("RequestAuthenticator line 232");
        RefreshableKeycloakSecurityContext session = new RefreshableKeycloakSecurityContext(deployment, tokenStore, oauth.getTokenString(), oauth.getToken(), oauth.getIdTokenString(), oauth.getIdToken(), oauth.getRefreshToken());
        final KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal = new KeycloakPrincipal<RefreshableKeycloakSecurityContext>(AdapterUtils.getPrincipalName(deployment, oauth.getToken()), session);
        completeOAuthAuthentication(principal);
        log.debugv("User ''{0}'' invoking ''{1}'' on client ''{2}''", principal.getName(), facade.getRequest().getURI(), deployment.getResourceName());
    }

    protected abstract void completeOAuthAuthentication(KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal);

    protected abstract void completeBearerAuthentication(KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal, String method);

    /**
     * After code is received, we change the session id if possible to guard against https://www.owasp.org/index.php/Session_Fixation
     *
     * @param create
     * @return
     */
    protected abstract String changeHttpSessionId(boolean create);

    protected void completeAuthentication(BearerTokenRequestAuthenticator bearer, String method) {
        System.out.println("RequestAuthenticator line 251");
        RefreshableKeycloakSecurityContext session = new RefreshableKeycloakSecurityContext(deployment, null, bearer.getTokenString(), bearer.getToken(), null, null, null);
        final KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal = new KeycloakPrincipal<RefreshableKeycloakSecurityContext>(AdapterUtils.getPrincipalName(deployment, bearer.getToken()), session);
        completeBearerAuthentication(principal, method);
        log.debugv("User ''{0}'' invoking ''{1}'' on client ''{2}''", principal.getName(), facade.getRequest().getURI(), deployment.getResourceName());
    }

}
