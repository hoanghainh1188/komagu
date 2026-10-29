package com.acme.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/admin/users")
public class AdminUserController {

    private UserDao userDao;

    @RequestMapping(value = "/{id}/delete", method = RequestMethod.POST)
    public String delete(@PathVariable("id") Long id) {
        userDao.deleteById(id); // LSA-EXPECT:BFLA
        return "redirect:/admin/users";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @RequestMapping(value = "/{id}/role", method = RequestMethod.POST)
    public String grant(@PathVariable("id") Long id, @RequestParam("role") String role) {
        userDao.updateRole(id, role); // LSA-EXPECT:SAFE-BFLA
        return "redirect:/admin/users";
    }
}
