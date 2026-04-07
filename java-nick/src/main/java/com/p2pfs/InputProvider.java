package com.p2pfs;

/**
 * Provides a single blocking readLine() used by PeerSession and ConsentManager
 * to read from a shared stdin queue without racing against the command loop.
 */
@FunctionalInterface
public interface InputProvider {
    String readLine();
}
