/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sg.cmsmattnickhassan.dao;

import com.sg.cmsmattnickhassan.Model.User;
import java.util.List;

/**
 *
 * @author hassan
 */
public interface UserDao {
    
    public User addUser(User user);
    public User updateUser(User user); 
    public void deleteUser(int userID);
    public User getUserById(int userID);
    public User getUserByUsername(String username);
 
    public List<User> getAllUsers();
    
    public List<User> getUserRole(int userID);
    
    
    
    
    
}
