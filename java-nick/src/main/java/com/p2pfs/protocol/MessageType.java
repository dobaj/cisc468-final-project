package com.p2pfs.protocol;

public enum MessageType {
    // Handshake / authentication (group-agreed names)
    AUTH_REQUEST,
    AUTH_RESPONSE,
    AUTH_SUCCESS,
    AUTH_FAIL,

    // Encrypted session envelope (all post-handshake traffic)
    ENCRYPTED,

    // File listing (no consent required)
    FILE_LIST_REQUEST,
    FILE_LIST_RESPONSE,

    // File pull: requester initiates
    FILE_REQUEST,
    FILE_ACCEPT,
    FILE_DENY,

    // File push: sender initiates (our extension for the send command)
    FILE_OFFER,
    FILE_OFFER_ACCEPT,
    FILE_OFFER_DENY,

    // File data transfer
    FILE_TRANSFER,
    FILE_COMPLETE,

    // Key migration (assignment requirement 6)
    KEY_MIGRATION,

    // General error
    ERROR
}
