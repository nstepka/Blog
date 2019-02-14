package com.sg.cmsmattnickhassan;

import com.sg.cmsmattnickhassan.Model.Role;
import com.sg.cmsmattnickhassan.Model.User;
import com.sg.cmsmattnickhassan.dao.RoleDao;
import com.sg.cmsmattnickhassan.dao.UserDao;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.inject.Inject;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class AdminController {

    @Inject
    RoleDao roles;

    @Inject
    PasswordEncoder encoder;

    @Inject
    UserDao users;

    @RequestMapping(value = "/admin", method = RequestMethod.GET)
    public String displayAdminPage(Model model) {
        model.addAttribute("user1", users.getUserById(1));
        model.addAttribute("users", users.getAllUsers());
        return "admin";
    }

    @RequestMapping(value = "/addUser", method = RequestMethod.POST)
    public String addUser(String username, String password) {
        User user = new User();
        user.setUserName(username);
        user.setPassword(encoder.encode(password));

        List<Role> userRoles = new ArrayList<>();
        userRoles.add(roles.getRoleByName("user"));
        user.setRoles(userRoles);

        users.addUser(user);

        return "redirect:/admin";
    }

    @RequestMapping(value = "/deleteUser", method = RequestMethod.POST)
    public String deleteUser(Integer id) {
        users.deleteUser(id);
        return "redirect:/admin";
    }

    @RequestMapping(value = "/editUser", method = RequestMethod.GET)
    public String editUserDisplay(Model model, Integer id, Integer error) {
        User user = users.getUserById(id);
        List<Role> roleList = roles.getAllRoles();
        model.addAttribute("user", user);
        model.addAttribute("roles", roleList);

        if (error != null) {
            if (error == 1) {
                model.addAttribute("error", "Passwords did not match, password was not updated.");
            }
        }
        return "editUser";
    }

    @RequestMapping(value = "/editUser", method = RequestMethod.POST)
    public String editUserAction(String[] roleIdList, Integer id) {
        User user = users.getUserById(id);

        List<Role> roleList = new ArrayList<>();
        for (String roleId : roleIdList) {
            Role role = roles.getRoleById(Integer.parseInt(roleId));
            roleList.add(role);
        }
        user.setRoles(roleList);
        users.updateUser(user);

        return "redirect:/admin";
    }

    @RequestMapping(value = "editPassword", method = RequestMethod.POST)
    public String editPassword(Integer id, String password, String confirmPassword) {
        User user = users.getUserById(id);

        if (password.equals(confirmPassword)) {
            user.setPassword(encoder.encode(password));
            users.updateUser(user);
            return "redirect:/admin";
        } else {
            return "redirect:/editUser?id=" + id + "&error=1";
        }
    }
}

