package com.united.TicketBoot.ticket;

import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.util.UUID;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.io.IOException;

@Service
public class TicketService {

    private final File ticketDir = new File("/tickets");
    private final ObjectMapper mapper = new ObjectMapper();

    public TicketService() {
        if (!ticketDir.exists()) {
            ticketDir.mkdirs();
        }
    }

    public Ticket createTicket(Ticket ticket) {
        String id = UUID.randomUUID().toString();
        ticket.setId(id);
        saveToFile(ticket);
        return ticket;
    }

    public Ticket getTicket(String id) {
        File f = new File(ticketDir, id);
        String ticket = "";
        byte[] fileContent = new byte[0];
        if (!f.exists()) return null;
        if (id.contains("flag") || id.contains("proc")) throw new RuntimeException("You are not allowed to read this file! Get outta here!");

        try {
            fileContent = Files.readAllBytes(f.toPath());
            ticket = new String(fileContent);
            return mapper.readValue(ticket, Ticket.class);
        } catch (IOException e) {
            StringBuilder hexDump = new StringBuilder();
            for (byte b : fileContent)
                hexDump.append(String.format("%02X ", b));

            throw new RuntimeException("Failed to parse file. Invalid file : " + ticket + "\n\nHere is the hex content:\n" + hexDump, e);
        }
    }

    private void saveToFile(Ticket ticket) {
        File f = new File(ticketDir, ticket.getId());
        try {
            mapper.writeValue(f, ticket);
        } catch (IOException ignored) {}
    }
}
