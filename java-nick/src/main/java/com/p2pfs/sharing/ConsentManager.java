package com.p2pfs.sharing;

import java.util.Scanner;

/**
 * Handles user consent for file operations via CLI prompts.
 */
public class ConsentManager {

    private final Scanner scanner;

    public ConsentManager(Scanner scanner) {
        this.scanner = scanner;
    }

    /**
     * Asks the user whether to accept an incoming file request.
     */
    public boolean promptFileRequest(String peerName, String fileName, String hash) {
        System.out.printf("%n[?] '%s' is requesting file '%s' (hash: %s)%n", peerName, fileName, truncateHash(hash));
        System.out.print("    Allow? [y/n]: ");
        return readYesNo();
    }

    /**
     * Asks the user whether to accept an incoming file offer (push).
     */
    public boolean promptFileOffer(String peerName, String fileName, long size, String hash) {
        System.out.printf("%n[?] '%s' wants to send you '%s' (%d bytes, hash: %s)%n",
                peerName, fileName, size, truncateHash(hash));
        System.out.print("    Accept? [y/n]: ");
        return readYesNo();
    }

    private boolean readYesNo() {
        String input = scanner.nextLine().trim().toLowerCase();
        return input.equals("y") || input.equals("yes");
    }

    private static String truncateHash(String hash) {
        if (hash.length() > 16) {
            return hash.substring(0, 16) + "...";
        }
        return hash;
    }
}
