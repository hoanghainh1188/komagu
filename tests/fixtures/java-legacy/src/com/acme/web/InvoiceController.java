package com.acme.web;

import java.security.Principal;
import org.hibernate.Session;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/invoices")
public class InvoiceController {

    private InvoiceDao invoiceDao;
    private Session session;

    @RequestMapping(value = "/{id}", method = RequestMethod.GET)
    public String show(@PathVariable("id") Long id, Model model) {
        model.addAttribute("invoice", invoiceDao.findById(id)); // LSA-EXPECT:BOLA
        return "invoice/show";
    }

    @RequestMapping(value = "/mine/{id}", method = RequestMethod.GET)
    public String mine(@PathVariable("id") Long id, Principal principal, Model model) {
        model.addAttribute("invoice", invoiceDao.findByIdAndOwner(id, principal.getName())); // LSA-EXPECT:SAFE-BOLA
        return "invoice/show";
    }

    @RequestMapping(value = "/search", method = RequestMethod.GET)
    public String search(@RequestParam("customer") String customer, Model model) {
        model.addAttribute("list", session.createQuery("from Invoice i where i.customer = '" + customer + "'").list()); // LSA-EXPECT:SQLI LSA-EXPECT:BOLA
        return "invoice/list";
    }
}
