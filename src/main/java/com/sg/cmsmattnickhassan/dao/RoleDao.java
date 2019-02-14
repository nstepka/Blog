/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sg.cmsmattnickhassan.dao;

import com.sg.cmsmattnickhassan.Model.Role;
import java.util.List;

/**
 *
 * @author hassan
 */
public interface RoleDao {
    
    public Role addRole(Role role);
    public Role getRoleByName(String roleName);    
    public Role updateRole(Role role);
    public void deleteRole(int roleID);
    public Role getRoleById(int roleID);
    public List<Role> getAllRoles();
    
}
