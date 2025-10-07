package com.united.TicketBoot.ticket;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

@Service
public class FirstClassTicketService {

    @Value("${ticketboot.superSecretPassword}")
    private String secret;

    public String getFlag(String param) throws IOException {
        if (secret.equals(param)) {
            return Files.readString(Path.of("/flag3.txt"));
        } else {
            return "Incorrect password";
        }
    }
}
