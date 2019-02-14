/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sg.cmsmattnickhassan;

import com.sg.cmsmattnickhassan.Model.Role;
import com.sg.cmsmattnickhassan.Model.User;
import com.sg.cmsmattnickhassan.dao.RoleDao;
import com.sg.cmsmattnickhassan.dao.UserDao;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import org.springframework.beans.factory.parsing.Location;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 *
 * @author hassan
 */
public class UserController {

   UserDao userDao;
   RoleDao roleDao;
   
   @Inject
   public UserController(UserDao userDao, RoleDao roleDao) {
       this.userDao = userDao;
       this.roleDao = roleDao;
   }
   
   
   @RequestMapping(value = "/displayCreateUserPage", method = RequestMethod.GET)
   public String displayCreateUserPage(Model model){
       List<User> userList = userDao.getAllUsers();
       List<Role> roles = roleDao.getAllRoles();
       model.addAttribute("userList" , userList);
       model.addAttribute("roles" , roles);
       return "createUser";
       
   }
   
       @RequestMapping(value= "/createUser", method =  RequestMethod.POST)
       public String createUser(HttpServletRequest request, Model model){
           User user = new User();
           user.setUserName(request.getParameter("userName"));
           userDao.addUser(user);
           
           String[] stringRoles = request.getParameterValues("role");
           List<Role> roles = new ArrayList<>();
           for(String oneRole : stringRoles) {
               int roleID = Integer.parseInt(oneRole);
               roles.add(roleDao.getRoleById(roleID));
           }
           user.setRoles(roles);
           user = userDao.addUser(user);
           model.addAttribute("user", user);
           model.addAttribute("roles", roles);
           return "redirect:displayCreateUserPage";
           
       }
       
         
       @RequestMapping(value =  "/displayUserDetails", method = RequestMethod.GET)
       public String displayUserDetails(HttpServletRequest request, Model model){
           String userIDParameter =  request.getParameter("userid");
           int userid = Integer.parseInt(userIDParameter);
           User user = userDao.getUserById(userid);
           model.addAttribute("user", user);
           return "userDetails";
       }
       
       @RequestMapping(value = "/deleteUser", method =  RequestMethod.DELETE)
       public String deleteUser(HttpServletRequest request){
           String userIDParameter = request.getParameter("userid");
           int userID = Integer.parseInt(userIDParameter);
           userDao.deleteUser(userID);
           return "redirect:displayCreateUserPage";
           
           
       }
       
       
       
       
       @RequestMapping(value = "/displayEditUserForm", method = RequestMethod.GET)
    public String displayEditUserForm(HttpServletRequest request, Model model) {
        String userIDParameter = request.getParameter("userID");
        int userID = Integer.parseInt(userIDParameter);
        User user = userDao.getUserById(userID);
        List<Role> roles = roleDao.getAllRoles();
        model.addAttribute("roles", roles);
        
        return "editUserForm";
    }
    
    @RequestMapping(value = "/editUser", method = RequestMethod.POST)
    public String editUser(@Valid @ModelAttribute("user") User user, BindingResult result, HttpServletRequest request) {

        if (result.hasErrors()) {
            return "editUserForm";
        }
        
        String userIDParameter = request.getParameter("userID");
        int userID = Integer.parseInt(userIDParameter);
        
        user = userDao.getUserById(userID);
        user.setUserName(request.getParameter("userName"));
      
        

        // list of roles to be taken in
        String[] userRoleIDs = request.getParameterValues("userRole");
        List<Role> roles = new ArrayList<>();
        for (String rID : userRoleIDs) {
            int roleID = Integer.parseInt(rID);
            roles.add(roleDao.getRoleById(roleID));
        }
        user.setRoles(roles);
        userDao.updateUser(user);

        return "redirect:displayUserPage";
    }
   

}
