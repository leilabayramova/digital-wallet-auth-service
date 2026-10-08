package com.example.digitalwalletauthservice.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Security audit trail. Logs only identifiers, never emails, passwords or tokens.
 */
public final class AuditLog {

    private static final Logger AUDIT = LoggerFactory.getLogger("AUDIT");

    private AuditLog() {
    }

    public static void event(String event, Long userId) {
        AUDIT.info("event={} userId={}", event, userId);
    }

    public static void event(String event, Long userId, String detail) {
        AUDIT.info("event={} userId={} detail={}", event, userId, detail);
    }
}
