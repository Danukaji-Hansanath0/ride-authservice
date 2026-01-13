package com.ride.authservice.dto;

import lombok.Getter;

@Getter
public enum CustomRole {
    CAR_OWNER(false, "Owns vehicles, sees revenue."), //1
    CUSTOMER(false,  "This is the users of the car rental service "), //2
    CUSTOMER_CORPORATE(false, "Corporate accounts, invoicing."),
    CUSTOMER_VIP(false, "Priority support, exclusive offers."),
    DRIVER(false, "Can accept rides, see earnings."), //3
    FRANCHISE_ADMIN(false, "Day-to-day operations, staff, vehicles."),
    FRANCHISE_OWNER(false, "Controls branding, pricing bands, commissions."), //4
    INTEGRATION_PARTNER(false, "API access, limited data visibility."),
    MERCHANT_ADMIN(false, "Manages products, orders, promotions."),
    MERCHANT_OWNER(false, "Full control over merchant settings, finances."),
    PLATFORM_ADMIN(false, "Manages franchises, feature flags, global pricing rules."), //5
    PLATFORM_AUDITOR(false, "Immutable read-only, compliance & investigations."),
    PLATFORM_DEVELOPER(false, "API access, logs, sandbox data, no business authority."),
    PLATFORM_FINANCE(false, "Global revenue, settlements, taxation exports."),
    PLATFORM_SUPER_ADMIN(false, "Absolute power. Realm config, billing models, legal shutdowns."),
    PLATFORM_SUPPORT(false, "Read-only + assisted actions. Disputes, audits."),
    SERVICE_ACCOUNT(false, "Non-human account for integrations."); //6;

    private final boolean isComposite;
    private final String description;

    CustomRole(boolean isComposite, String description) {
        this.isComposite = isComposite;
        this.description = description;
    }

    // Optional: Method to get the role name as a string (if needed)
    public String getRoleName() {
        return this.name();
    }
}
