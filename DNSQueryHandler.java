package ca.ubc.cs317.dnslookup;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.LinkedHashSet;
import java.util.Random;
import java.util.Set;

public class DNSQueryHandler {

    private static final int DEFAULT_DNS_PORT = 53;
    private static DatagramSocket socket;
    private static boolean verboseTracing = false;

    private static final Random random = new Random();

    /**
     * Sets up the socket and set the timeout to 5 seconds
     *
     * @throws SocketException if the socket could not be opened, or if there was an
     *                         error with the underlying protocol
     */
    public static void openSocket() throws SocketException {
        socket = new DatagramSocket();
        socket.setSoTimeout(5000);
    }

    /**
     * Closes the socket
     */
    public static void closeSocket() {
        socket.close();
    }

    /**
     * Set verboseTracing to tracing
     */
    public static void setVerboseTracing(boolean tracing) {
        verboseTracing = tracing;
    }

    /**
     * Builds the query, sends it to the server, and returns the response.
     *
     * @param message Byte array used to store the query to DNS servers.
     * @param server  The IP address of the server to which the query is being sent.
     * @param node    Host and record type to be used for search.
     * @return A DNSServerResponse Object containing the response buffer and the transaction ID.
     * @throws IOException if an IO Exception occurs
     */
    public static DNSServerResponse buildAndSendQuery(byte[] message, InetAddress server,
                                                      DNSNode node) throws IOException {
        // ****DNS HEADER****
        // |ID (16)|
        int queryID = random.nextInt((int) Math.pow(2,16)); // 2-byte value
        message[0] = (byte) (queryID >>> 8);
        message[1] = (byte) queryID;

        // |QR| Opcode (4)|AA|TC|RD|
        byte QR = 0; // query (0), or a response (1)
        byte Opcode = 0; // standard (0), inverse (1), status request (2)
        byte AA = 0; // authoritative answer
        byte TC = 0; // truncation
        byte RD = 0; // recursion desired
        message[2] = (byte) ((QR << 7) | (Opcode << 3) | (AA << 2) | (TC << 1) | RD);

        // |RA| Z (3)| RCODE (4)|
        byte RA = 0; // recursion available
        byte Z = 0; // (reserved for future use)
        byte Rcode = 0; // response code
        message[3] = (byte) ((RA << 7) | (Z << 4) | Rcode);

        // |QDCOUNT (16)|
        short QDcount = 1; // number of questions
        message[4] = (byte) (QDcount >>> 8);
        message[5] = (byte) QDcount;

        // |ANCOUNT (16)|
        message[6] = message[7] = 0; // number of answers

        // |NSCOUNT (16)|
        message[8] = message[9] = 0; // number of name server resource records

        // |ARCOUNT (16)|
        message[10] = message[11] = 0; // number of entries in the additional records section

        // ****QNAME****
        String[] qname = node.getHostName().split("\\.");
        int msgIndex = 12;
        for (int i = 0; i<qname.length; i++) { // construct the DNS labels
            int strlen = qname[i].length();
            message[msgIndex] = (byte) strlen;
            msgIndex++;
            for (int c = 0; c < strlen; c++) {
                message[msgIndex+c] = (byte) qname[i].charAt(c);
            }
            msgIndex += strlen;
        }
        message[msgIndex] = 0; // end of qname

        // QTYPE (16)
        short qtype = (short) node.getType().getCode();
        message[msgIndex+1] = (byte) (qtype >>> 8);
        message[msgIndex+2] = (byte) qtype;
        
        // QCLASS (16)
        short qclass = 1; // (1) for internet. All others are rarely used. Could also be (255) any class.
        message[msgIndex+3] = (byte) (qclass >>> 8);
        message[msgIndex+4] = (byte) qclass;

        // *** Send and receive the response ***
        String questionTraceString = "Query ID     " 
                                   + Integer.toString(queryID) + " "
                                   + node.getHostName() + "  "
                                   + RecordType.getByCode((int) qtype) + " --> "
                                   + server.getHostAddress();
        if (verboseTracing) {
            System.out.println(""); 
            System.out.println("");
            System.out.println(questionTraceString);
        }

        DatagramPacket msgPacket = new DatagramPacket(message, msgIndex + 5, server, DEFAULT_DNS_PORT);
        socket.send(msgPacket);

        byte[] response = new byte[1024];
        DatagramPacket responsePacket = new DatagramPacket(response, 1024);
        try {
            socket.receive(responsePacket);
        } catch (SocketTimeoutException e) {
            // resend the packet once if timeout occurs.
            if (verboseTracing) {
                System.out.println("");
                System.out.println("");
                System.out.println(questionTraceString);
            }
            socket.send(msgPacket);
            socket.receive(responsePacket);
        }
        
        return new DNSServerResponse(ByteBuffer.wrap(response), queryID);
    }

    /**
     * Decodes the DNS server response and caches it.
     *
     * @param transactionID  Transaction ID of the current communication with the DNS server
     * @param responseBuffer DNS server's response
     * @param cache          To store the decoded server's response
     * @return A set of resource records corresponding to the name servers of the response.
     */
    public static Set<ResourceRecord> decodeAndCacheResponse(int transactionID, ByteBuffer responseBuffer, DNSCache cache) {
        byte[] response = new byte[responseBuffer.remaining()];
        responseBuffer.get(response, 0, response.length);

        // *** Extract Header section ***
        int ID = (int) (((response[0] & 0xFF) << 8) | (response[1] & 0xFF)); // randomly generated 16-bit identifier from initial query
        
        boolean QR  = (response[2] & 0x80) >>> 7 == 1;   // 0 if query, 1 if response
        int Opcode  = (response[2] & 0x78) >>> 3;        // the Opcode; will likely be 0 for standard query.
        boolean AA  = (response[2] & 0x4) >>> 2 == 1;    // true if the response is authoritative
        boolean TC  = (response[2] & 0x2) >>> 1 == 1;    // true if the response is truncated; not handled by this implementation.
        boolean RD  = (response[2] & 0x1) == 1;          // true if the query wanted the name server to recursively query
        if (TC || !QR) { return null; }

        boolean RA  = (response[3] & 0x80) >>> 7 == 1;   // true if the responding server can do recursive queries              
        int Z       = (response[3] & 0x70) >>> 4;        // bytes reserved for future use
        int RCODE   = (response[3] & 0xF);               // the response code; signals either no error or some kind of error.
        if (RCODE != 0) { return null; }

        int QDCOUNT = (int) (((response[4] & 0xFF) << 8) | (response[5] & 0xFF));   // number of entries in the QUESTION section.
        int ANCOUNT = (int) (((response[6] & 0xFF) << 8) | (response[7] & 0xFF));   // number of entries in the ANSWER section.
        int NSCOUNT = (int) (((response[8] & 0xFF) << 8) | (response[9] & 0xFF));   // number of name server RR's in the AUTHORITY section.
        int ARCOUNT = (int) (((response[10] & 0xFF) << 8) | (response[11] & 0xFF)); // number of RR's in the ADDITIONAL section.
        if (AA && RCODE == 0 && ANCOUNT == 0) { return null; } // authoritative response with no answers

        int currIdx = 12;


        // *** Extract Question section ***
        String QNAME = "";
        while (response[currIdx] != 0) {
            // Pointer; recurse into it
            if ((response[currIdx] & 0xFF) >>> 6 == 3) {  
                int offset = (int) ((response[currIdx] & 0x3F) << 8) | (response[currIdx+1] & 0xFF);
                QNAME += getNameString(offset, response);
                currIdx += 1; // pointers are always 2 bytes long
                break;
            }
            // Not a pointer; directly translate from ASCII to the string
            else {
                int strlen = (int) response[currIdx];
                currIdx++;
                for (int c = 0; c < strlen; c++) {
                    QNAME += (char) response[currIdx];
                    currIdx++;
                }
                QNAME += ".";
            }
        }
        if ((QNAME != null) && (QNAME.length() > 0) && QNAME.endsWith(".")) { 
            QNAME = QNAME.substring(0, QNAME.length() - 1); // remove the last character of the string
        }
        currIdx++; // set to QTYPE's first byte
        
        int QTYPE  = (int) (((response[currIdx] & 0xFF) << 8) | (response[currIdx+1] & 0xFF));   // question type of query being responded to
        int QCLASS = (int) (((response[currIdx+2] & 0xFF) << 8) | (response[currIdx+3] & 0xFF)); // question class of query being responded to
        currIdx += 4; 

        if (verboseTracing) {
            String responseTraceString = "Response ID: "
                                       + Integer.toString(transactionID) + " Authoritative = "
                                       + (AA ? "true" : "false");
            System.out.println(responseTraceString);
        }
        
        Set<ResourceRecord> rrs = new LinkedHashSet<ResourceRecord>();

        // *** Extract Answer section ***
        // cache all answers found. 
        if (verboseTracing) { System.out.println("  Answers (" + ANCOUNT + ")"); }
        
        for (int i = 0; i < ANCOUNT; i++) {
            String NAME = "";
            while (response[currIdx] != 0) {
                // Pointer
                if ((response[currIdx] & 0xFF) >>> 6 == 3) {
                    int offset = (int) ((response[currIdx] & 0x3F) << 8) | (response[currIdx+1] & 0xFF);
                    NAME += getNameString(offset, response);
                    currIdx += 1; 
                    break;
                }
                // Not a pointer
                else {
                    int strlen = (int) response[currIdx];
                    currIdx++;
                    for (int c = 0; c < strlen; c++) {
                        NAME += (char) response[currIdx];
                        currIdx++;
                    }
                    NAME += ".";
                }
            }
            if ((NAME != null) && (NAME.length() > 0) && NAME.endsWith(".")) {        
                NAME = NAME.substring(0, NAME.length() - 1); 
            }
            currIdx++;

            int TYPE = (int) (((response[currIdx] & 0xFF) << 8) | (response[currIdx+1] & 0xFF));         // RDATA type; defines what the RDATA meaning is
            RecordType recordType = RecordType.getByCode(TYPE);
            int CLASS = (int) (((response[currIdx+2] & 0xFF) << 8) | (response[currIdx+3] & 0xFF));      // RDATA class; likely just 1 for "Internet Address"
            int TTL = (int) (((response[currIdx+4] & 0xFF) << 24)                                        // how long the RR can be cached before discarding.
                           | ((response[currIdx+5] & 0xFF) << 16)
                           | ((response[currIdx+6] & 0xFF) << 8)
                           | (response[currIdx+7] & 0xFF));        
            int RDLENGTH = (int) (((response[currIdx+8] & 0xFF) << 8) | (response[currIdx+9] & 0xFF));   // length of the RDATA field.
            currIdx += 10;

            // *** Handle RDATA ***
            ResourceRecord ansRecord = rdataToRR(currIdx, response, recordType, RDLENGTH, NAME, TTL);
            cache.addResult(ansRecord);

            if (AA && (recordType == RecordType.A || recordType == RecordType.AAAA)) {
                ResourceRecord addRecordQNAME = rdataToRR(currIdx, response, recordType, RDLENGTH, QNAME, TTL);
                cache.addResult(addRecordQNAME);
            }

            currIdx += RDLENGTH;

            verbosePrintResourceRecord(ansRecord, TYPE);
        }


        // *** Extract Authority section ***
        // adds the records here to the set that will be returned. 
        if (verboseTracing) { System.out.println("  Nameservers (" + NSCOUNT + ")"); }
        for (int i = 0; i < NSCOUNT; i++) {
            String NAME = "";
            while (response[currIdx] != 0) {
                // Pointer
                if ((response[currIdx] & 0xFF) >>> 6 == 3) {
                    int offset = (int) ((response[currIdx] & 0x3F) << 8) | (response[currIdx+1] & 0xFF);
                    NAME += getNameString(offset, response);
                    currIdx += 1; 
                    break;
                }
                // Not a pointer
                else {
                    int strlen = (int) response[currIdx];
                    currIdx++;
                    for (int c = 0; c < strlen; c++) {
                        NAME += (char) response[currIdx];
                        currIdx++;
                    }
                    NAME += ".";
                }
            }
            if ((NAME != null) && (NAME.length() > 0) && NAME.endsWith(".")) {        
                NAME = NAME.substring(0, NAME.length() - 1); 
            }
            currIdx++;

            int TYPE = (int) (((response[currIdx] & 0xFF) << 8) | (response[currIdx+1] & 0xFF));         // RDATA type; defines what the RDATA meaning is
            RecordType recordType = RecordType.getByCode(TYPE);
            int CLASS = (int) (((response[currIdx+2] & 0xFF) << 8) | (response[currIdx+3] & 0xFF));      // RDATA class; likely just 1 for "Internet Address"
            int TTL = (int) (((response[currIdx+4] & 0xFF) << 24)                                        // how long the RR can be cached before discarding.
                           | ((response[currIdx+5] & 0xFF) << 16)
                           | ((response[currIdx+6] & 0xFF) << 8)
                           | (response[currIdx+7] & 0xFF));        
            int RDLENGTH = (int) (((response[currIdx+8] & 0xFF) << 8) | (response[currIdx+9] & 0xFF));   // length of the RDATA field.
            currIdx += 10;

            ResourceRecord authRecord = rdataToRR(currIdx, response, recordType, RDLENGTH, NAME, TTL);
            currIdx += RDLENGTH;
            rrs.add(authRecord);

            verbosePrintResourceRecord(authRecord, TYPE);
        }


        // *** Extract Additional section ***
        // cache all records in this section.
        if (verboseTracing) { System.out.println("  Additional Information (" + ARCOUNT + ")"); }
        for (int i = 0; i < ARCOUNT; i++) {
            String NAME = "";
            while (response[currIdx] != 0) {
                // Pointer
                if ((response[currIdx] & 0xFF) >>> 6 == 3) {
                    int offset = (int) ((response[currIdx] & 0x3F) << 8) | (response[currIdx+1] & 0xFF);
                    NAME += getNameString(offset, response);
                    currIdx += 1; 
                    break;
                }
                // Not a pointer
                else {
                    int strlen = (int) response[currIdx];
                    currIdx++;
                    for (int c = 0; c < strlen; c++) {
                        NAME += (char) response[currIdx];
                        currIdx++;
                    }
                    NAME += ".";
                }
            }
            if ((NAME != null) && (NAME.length() > 0) && NAME.endsWith(".")) {        
                NAME = NAME.substring(0, NAME.length() - 1); 
            }
            currIdx++;

            int TYPE = (int) (((response[currIdx] & 0xFF) << 8) | (response[currIdx+1] & 0xFF));         // RDATA type; defines what the RDATA meaning is
            RecordType recordType = RecordType.getByCode(TYPE);
            int CLASS = (int) (((response[currIdx+2] & 0xFF) << 8) | (response[currIdx+3] & 0xFF));      // RDATA class; likely just 1 for "Internet Address"
            int TTL = (int) (((response[currIdx+4] & 0xFF) << 24)                                        // how long the RR can be cached before discarding.
                           | ((response[currIdx+5] & 0xFF) << 16)
                           | ((response[currIdx+6] & 0xFF) << 8)
                           | (response[currIdx+7] & 0xFF));        
            int RDLENGTH = (int) (((response[currIdx+8] & 0xFF) << 8) | (response[currIdx+9] & 0xFF));   // length of the RDATA field.
            currIdx += 10;

            ResourceRecord addRecord = rdataToRR(currIdx, response, recordType, RDLENGTH, NAME, TTL);
            currIdx += RDLENGTH;
            cache.addResult(addRecord);

            verbosePrintResourceRecord(addRecord, TYPE);
        }

        return rrs;
    }

    /**
     * Formats and prints record details (for when trace is on)
     *
     * @param record The record to be printed
     * @param rtype  The type of the record to be printed
     */
    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    /**
     * At the currIdx, extracts the name element from the response array.
     * Assumes that the currIdx and response are well-formed and aligned.
     * Used mainly when there is a pointer.
     * 
     * @param currIdx  The index where the name definition starts
     * @param response The response in byte array form
     * @return The name in string representation
     */
    private static String getNameString(int currIdx, byte[] response) {
        String result = "";
        while(response[currIdx] != 0) {
            // Pointer; needs to recurse.
            if ((response[currIdx] & 0xFF) >>> 6 == 3) {
                int offset = (int) ((response[currIdx] & 0x3F) << 8) | (response[currIdx+1] & 0xFF);
                result += getNameString(offset, response);
                currIdx += 1;
                break;
            }
            // Not a pointer; directly translate from ASCII to the string
            else {
                int strlen = (int) response[currIdx];
                currIdx++;
                for (int c = 0; c < strlen; c++) {
                    result += (char) response[currIdx];
                    currIdx++;
                }
                result += ".";
            }
        }
        if ((result != null) && (result.length() > 0) && result.endsWith(".")) {
            result = result.substring(0, result.length() - 1);
        }
        return result;
    }

    /**
     * At the currIdx, extracts a ResourceRecord from the response array.
     * Assumes that the currIdx and response are well-formed and aligned.
     * 
     * @param currIdx  The index where the RDATA starts
     * @param response The response in byte array form
     * @param type     The type of the RDATA
     * @param RDLENGTH The length of RDATA
     * @return The RR corresponding to the RDATA
     */
    private static ResourceRecord rdataToRR(int currIdx, byte[] response, RecordType type, 
                                            int RDLENGTH, String NAME, int TTL) {
        switch (type) {
            case A:
                String ipv4 = "";
                for (int b = 0; b < RDLENGTH; b++) {
                    ipv4 += Integer.toString((int) (response[currIdx+b] & 0xFF)) + ".";
                }
                if ((ipv4 != null) && (ipv4.length() > 0) && ipv4.endsWith(".")) {     
                    ipv4 = ipv4.substring(0, ipv4.length() - 1); // remove trailing .
                }
                try {
                    InetAddress add = InetAddress.getByName(ipv4);
                    return new ResourceRecord(NAME, type, TTL, add);
                } catch (UnknownHostException e) {
                    return new ResourceRecord(NAME, type, TTL, ipv4);
                }
            case AAAA:
                String ipv6 = "";
                for (int b = 0; b < RDLENGTH; b++) {
                    if (b % 2 == 0) { // The first byte in the 2 byte sequence between :'s
                        ipv6 += Integer.toHexString((int) (response[currIdx+b] & 0xFF));
                    } 
                    else {            // The second byte in the 2 byte sequence between :'s
                        ipv6 += String.format("%02X", (int) (response[currIdx+b] & 0xFF)) + ":";
                    }
                }
                if ((ipv6 != null) && (ipv6.length() > 0) && ipv6.endsWith(":")) {     
                    ipv6 = ipv6.substring(0, ipv6.length() - 1); // remove trailing :
                }
                try {
                    InetAddress add = InetAddress.getByName(ipv6);
                    return new ResourceRecord(NAME, type, TTL, add);
                } catch (UnknownHostException e) {
                    return new ResourceRecord(NAME, type, TTL, ipv6);
                }
            case NS:
            case CNAME:
                return new ResourceRecord(NAME, type, TTL, getNameString(currIdx, response));
            default:
                return new ResourceRecord(NAME, type, TTL, "----");
        }
    }
}

