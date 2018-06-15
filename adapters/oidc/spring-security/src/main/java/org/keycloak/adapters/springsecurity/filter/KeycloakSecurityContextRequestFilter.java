/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.adapters.springsecurity.filter;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.facade.SimpleHttpFacade;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class KeycloakSecurityContextRequestFilter extends GenericFilterBean implements ApplicationContextAware {

    private static final String FILTER_APPLIED = KeycloakSecurityContext.class.getPackage().getName() + ".token-refreshed";

    private ApplicationContext applicationContext;
    private AdapterDeploymentContext deploymentContext;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        if (request.getAttribute(FILTER_APPLIED) != null) {
            System.out.println("KeycloakSecurityContext line 53 doFilter");
            filterChain.doFilter(request, response);
            return;
        }

        request.setAttribute(FILTER_APPLIED, Boolean.TRUE);
        System.out.println("KeycloakSecurityContext line 59 filterApplied");

        KeycloakSecurityContext keycloakSecurityContext = getKeycloakPrincipal();

        if (keycloakSecurityContext instanceof RefreshableKeycloakSecurityContext) {
            System.out.println("KeycloakSecurityContext line 64");
            RefreshableKeycloakSecurityContext refreshableSecurityContext = (RefreshableKeycloakSecurityContext) keycloakSecurityContext;

            if (refreshableSecurityContext.isActive()) {
                System.out.println("KeycloakSecurityContext line 68");
                KeycloakDeployment deployment = resolveDeployment(request, response);

                if (deployment.isAlwaysRefreshToken()) {
                    System.out.println("KeycloakSecurityContext line 72");
                    if (refreshableSecurityContext.refreshExpiredToken(false)) {
                        System.out.println("KeycloakSecurityContext line 75");
                        request.setAttribute(KeycloakSecurityContext.class.getName(), refreshableSecurityContext);
                    } else {
                        System.out.println("KeycloakSecurityContext line 77");
                        clearAuthenticationContext();
                    }
                }
            } else {
                System.out.println("KeycloakSecurityContext line 82");
                clearAuthenticationContext();
            }
        }
        System.out.println("KeycloakSecurityContext line 86");
        filterChain.doFilter(request, response);
    }

    @Override
    protected void initFilterBean() throws ServletException {
        System.out.println("KeycloakSecurityContext line 92");
        deploymentContext = applicationContext.getBean(AdapterDeploymentContext.class);
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        System.out.println("KeycloakSecurityContext line 98");

        this.applicationContext = applicationContext;
    }

    private KeycloakSecurityContext getKeycloakPrincipal() {
        System.out.println("KeycloakSecurityContext line 104");

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null) {
            System.out.println("KeycloakSecurityContext line 109");

            Object principal = authentication.getPrincipal();

            if (principal instanceof KeycloakPrincipal) {
                System.out.println("KeycloakSecurityContext line 115");

                return KeycloakPrincipal.class.cast(principal).getKeycloakSecurityContext();
            }
        }
        System.out.println("KeycloakSecurityContext line 119");

        return null;
    }

    private KeycloakDeployment resolveDeployment(ServletRequest servletRequest, ServletResponse servletResponse) {
        System.out.println("KeycloakSecurityContext line 125");

        return deploymentContext.resolveDeployment(new SimpleHttpFacade(HttpServletRequest.class.cast(servletRequest), HttpServletResponse.class.cast(servletResponse)));
    }

    private void clearAuthenticationContext() {
        System.out.println("KeycloakSecurityContext line 131");


        SecurityContextHolder.clearContext();
    }
}
