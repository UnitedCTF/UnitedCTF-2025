package com.united.TicketBoot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.data.rest.RepositoryRestMvcAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
public class TicketBootApplication {

	public static void main(String[] args) {
		SpringApplication.run(TicketBootApplication.class, args);
	}

}
