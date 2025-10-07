package com.united.TicketBoot.springconfig;

import io.swagger.v3.oas.models.*;
import io.swagger.v3.oas.models.info.*;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.media.*;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenAPIConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info().title("TicketBoot Service Doc")
                        .description("This service allows the users to create and view their tickets")
                        .version("1.0.0")
                        .contact(new Contact()
                                .name("Christopher Columbus")))
                .servers(List.of(new Server().url("http://localhost:8080").description("Generated server url")))
                .components(new Components().addSchemas("Ticket", new Schema<>()
                        .type("object")
                        .addProperty("id", new StringSchema())
                        .addProperty("name", new StringSchema().minLength(1))
                        .addProperty("couponCode", new StringSchema())
                        .required(List.of("name"))))
                .paths(new Paths()
                        .addPathItem("/",
                                new PathItem()
                                        .get(new Operation()
                                                .description("This operation displays the index file")
                                                .tags(List.of("ticket-controller"))
                                                .operationId("getIndex")
                                                .responses(new ApiResponses()
                                                        .addApiResponse("200", new ApiResponse()
                                                                .description("OK")
                                                                .content(new Content()
                                                                        .addMediaType("*/*", new MediaType()
                                                                                .schema(new StringSchema())))))))
                        .addPathItem("/ticket",
                                new PathItem()
                                        .get(new Operation()
                                                .description("This operation reads a ticket from the /tickets/{id} folder")
                                                .tags(List.of("ticket-controller"))
                                                .operationId("getTicket")
                                                .parameters(List.of(new Parameter()
                                                        .name("ticketId")
                                                        .in("query")
                                                        .required(true)
                                                        .schema(new StringSchema())))

                                                .responses(new ApiResponses()
                                                        .addApiResponse("200", new ApiResponse()
                                                                .description("OK")
                                                                .content(new Content()
                                                                        .addMediaType("*/*", new MediaType()
                                                                                .schema(new StringSchema()))))))
                                        .post(new Operation()
                                                .description("This operation creates a new ticket in the /tickets/{id} folder")
                                                .tags(List.of("ticket-controller"))
                                                .operationId("createTicket")
                                                .parameters(List.of(new Parameter()
                                                        .name("ticket")
                                                        .in("query")
                                                        .required(true)
                                                        .schema(new Schema<>().$ref("#/components/schemas/Ticket"))))
                                                .responses(new ApiResponses()
                                                        .addApiResponse("201", new ApiResponse()
                                                                .description("Created")
                                                                .content(new Content()
                                                                        .addMediaType("*/*", new MediaType()
                                                                                .schema(new StringSchema()))))))));
    }
}
