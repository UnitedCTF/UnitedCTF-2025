package com.united.TicketBoot.ticket;

import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

@Controller
public class TicketController {

    @Autowired
    private TicketService ticketService;

    @Value("${ticketboot.secondFlag}")
    private String FLAG2;

    @GetMapping("/")
    @ResponseStatus(HttpStatus.OK)
    public String getIndex(Model model) {
        model.addAttribute("ticket", new Ticket());
        return "index";
    }

    @PostMapping("/ticket")
    @ResponseStatus(HttpStatus.CREATED)
    public String createTicket(Model model, @Valid @ModelAttribute Ticket ticket, BindingResult result) {
        if (result.hasErrors()) {
            return "index";
        }

        if (COUPON_CODE.equals(ticket.getCouponCode())) {
            ticket.setFlag(FLAG2);
            Ticket response = ticketService.createTicket(ticket);
            model.addAttribute("ticketId", ticket.getId());
            model.addAttribute("ticket", new Ticket());
        } else {
            result.rejectValue("couponCode", "invalid.coupon", "Invalid coupon code!");
        }
        return "index";
    }

    @GetMapping("/ticket")
    @ResponseStatus(HttpStatus.OK)
    public String getTicket(Model model, @RequestParam String ticketId) {
        Ticket ticket = ticketService.getTicket(ticketId);
        model.addAttribute("ticket", ticket);

        return "index";
    }

    @ExceptionHandler(Exception.class)
    public String handleErrors(Exception ex, Model model) {
        model.addAttribute("errorMessage", ex.getMessage());
        return "error";
    }

    @ModelAttribute
    public void hideShip(Model model,
                         @CookieValue(name = "hideShip", defaultValue = "false") String hideShipCookie) {
        model.addAttribute("hideShip", "true".equalsIgnoreCase(hideShipCookie));
    }

    private final String COUPON_CODE = "FREE_CRUISE_TICKETS_a0e5fce92e91b0d1ba55dcc10732d85d";
}
