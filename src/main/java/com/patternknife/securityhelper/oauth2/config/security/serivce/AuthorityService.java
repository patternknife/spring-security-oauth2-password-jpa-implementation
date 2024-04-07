package com.patternknife.securityhelper.oauth2.config.security.serivce;

import org.springframework.context.annotation.Bean;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class AuthorityService {

    public boolean hasAnyAdminRole() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getAuthorities() == null) {
            return false;
        }
        return authentication.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().endsWith("_ADMIN"));
    }

    private boolean hasRoleOrSuperAdmin(String role) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getAuthorities() == null) {
            return false;
        }

        // Check for SUPER_ADMIN role or the specific role
        return authentication.getAuthorities().stream()
                .anyMatch(authority -> "SUPER_ADMIN".equals(authority.getAuthority())
                        || authority.getAuthority().equals(role));
    }

    public boolean hasAnyOfRoles(String[] roles) {
        for (String role : roles) {
            if (hasRoleOrSuperAdmin(role)) {
                return true;
            }
        }
        return false;
    }
    public boolean hasRole(String role) {
        return hasRoleOrSuperAdmin(role);
    }

    @Bean
    public String[] rolesWithExcel() {
        return new String[] {"CLINIC_ADMIN", "BRAND_PRODUCT_ADMIN" }; // Replace with actual roles
    }

}