package com.p2pfs.sharing;

import com.p2pfs.InputProvider;

// prompts the user to accept or reject incoming file requests and offers
public class ConsentManager {

    private final InputProvider input;

    public ConsentManager(InputProvider input) {
        this.input = input;
    }

    public boolean promptFileRequest(String peerName, String fileName, String hash) {
        System.out.printf("%n[?] '%s' is requesting file '%s' (hash: %s)%n", peerName, fileName, truncateHash(hash));
        System.out.print("    Allow? [y/n]: ");
        return readYesNo();
    }

    public boolean promptFileOffer(String peerName, String fileName, long size, String hash) {
        System.out.printf("%n[?] '%s' wants to send you '%s' (%d bytes, hash: %s)%n",
                peerName, fileName, size, truncateHash(hash));
        System.out.print("    Accept? [y/n]: ");
        return readYesNo();
    }

    private boolean readYesNo() {
        System.out.flush();
        String line = input.readLine().trim().toLowerCase();
        return line.equals("y") || line.equals("yes");
    }

    private static String truncateHash(String hash) {
        if (hash == null) return "(no hash)";
        if (hash.length() > 16) return hash.substring(0, 16) + "...";
        return hash;
    }
}
