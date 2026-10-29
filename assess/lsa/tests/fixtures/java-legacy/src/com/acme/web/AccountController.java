package com.acme.web;

import com.acme.model.Account;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/account")
public class AccountController {

    private AccountDao accountDao;

    @RequestMapping(value = "/save", method = RequestMethod.POST)
    public String save(@ModelAttribute Account account) { // LSA-EXPECT:MASS
        accountDao.save(account);
        return "redirect:/account";
    }

    @RequestMapping(value = "/rename", method = RequestMethod.POST)
    public String rename(@ModelAttribute RenameForm form) { // LSA-EXPECT:SAFE-MASS
        accountDao.rename(form.getId(), form.getName());
        return "redirect:/account";
    }

    @RequestMapping(value = "/api", method = RequestMethod.PUT)
    @ResponseBody
    public Account update(@RequestBody Account account) { // LSA-EXPECT:MASS
        return accountDao.save(account);
    }
}
