package ch.horloger.controller;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import javax.servlet.http.HttpServletRequest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class HorlogerController {

    private static final Logger logger = LogManager.getLogger(HorlogerController.class);

    @GetMapping("/")
    public String home(Model model) {
        model.addAttribute("currentTime", LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss")));
        logger.info("Homepage accessed");
        return "index";
    }

    @GetMapping("/about")
    public String about(Model model) {
        logger.info("About page accessed");
        return "about";
    }

    @GetMapping("/contact")
    public String contact(Model model) {
        logger.info("Contact page accessed");
        return "contact";
    }

    @PostMapping("/contact")
    public String submitContact(@RequestParam String name, 
                               @RequestParam String email, 
                               @RequestParam String message,
                               HttpServletRequest request,
                               Model model) {
        
        String userAgent = request.getHeader("User-Agent");
        String clientInfo = request.getHeader("X-Client-Info");
        
        // VULNERABILITY: Log4j JNDI injection
        // The logger will process JNDI lookups in the logged message
        logger.info("Contact form submitted by: {} | Email: {} | Message: {} | UserAgent: {} | ClientInfo: {}", 
                   name, email, message, userAgent, clientInfo);
        
        model.addAttribute("message", "Merci! Votre message a été reçu avec de la précision Suisse!");
        model.addAttribute("success", true);
        
        return "contact";
    }

    @GetMapping("/collection")
    public String collection(Model model) {
        logger.info("Collection page accessed");
        return "collection";
    }

    @GetMapping("/timepiece/{id}")
    public String timepiece(@PathVariable String id, Model model) {
        // VULNERABILITY: Log4j JNDI injection through path parameter
        logger.info("Timepiece viewed: {}", id);
        model.addAttribute("timepieceId", id);
        return "timepiece";
    }

    @GetMapping("/search")
    public String search(@RequestParam(required = false) String q, Model model) {
        if (q != null && !q.isEmpty()) {
            // VULNERABILITY: Log4j JNDI injection through search parameter
            logger.info("Search performed for: {}", q);
            model.addAttribute("searchTerm", q);
        }
        return "search";
    }
} 