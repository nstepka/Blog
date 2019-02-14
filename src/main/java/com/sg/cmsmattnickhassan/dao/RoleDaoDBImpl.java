/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sg.cmsmattnickhassan.dao;

import com.sg.cmsmattnickhassan.Model.Role;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.transaction.annotation.Transactional;

/**
 *
 * @author hassan
 */
public class RoleDaoDBImpl implements RoleDao{

    private JdbcTemplate jdbc;

    public void setJdbcTemplate(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }
    
    private static final String SQL_INSERT_ROLE
            = "INSERT INTO Role "
            + "(roleName) "
            + "values (?)";
    
    @Override
    @Transactional
    public Role addRole(Role role) {
        jdbc.update(SQL_INSERT_ROLE,
            role.getRoleType());
        //made it all one line instead of declaring an int
        
        role.setRoleID(jdbc.queryForObject("select LAST_INSERT_ID()",
                Integer.class));
                
        return role;
    }

    
    private static final String SQL_UPDATE_ROLE
            = "UPDATE Role "
            + "SET roleName = ? "
            + "WHERE Roleid = ?";
    
    
    
    @Override
    @Transactional
    public Role updateRole(Role role) {
        
        jdbc.update(SQL_UPDATE_ROLE, role.getRoleType(), role.getRoleID());
                
        return role;
    
    }
    
    private static final String SQL_DELETE_ROLE_FROM_USER_ROLE 
            = "DELETE FROM UserRole "
            + "WHERE Roleid = ?";
    
    private static final String SQL_DELETE_ROLE 
            = "DELETE FROM Role "
            + "WHERE Roleid = ?";
            
    
    
    @Override
    @Transactional
    public void deleteRole(int roleID) {
        jdbc.update(SQL_DELETE_ROLE_FROM_USER_ROLE, roleID);
        jdbc.update(SQL_DELETE_ROLE, roleID);
    
    
    }
    
    private static String SQL_GET_ROLE
            = "SELECT * "
            + "FROM Role "
            + "WHERE Roleid = ?";
    
    @Override
    public Role getRoleById(int roleID) {
        try {
            return jdbc.queryForObject(SQL_GET_ROLE,
                    new RoleMapper(), roleID);
        } catch (EmptyResultDataAccessException ex) {
            // there were no results for the given contact id - we just 
            // want to return null in this case
            return null;
        }
    
    }
    
    private static final String SQL_GET_ALL_ROLE
            = "SELECT * "
            + "FROM Role";
    
    @Override
    public List<Role> getAllRoles() {
        return jdbc.query(SQL_GET_ALL_ROLE, new RoleMapper());        
    }

    @Override
    public Role getRoleByName(String roleName) {
        return jdbc.queryForObject("SELECT * FROM `Role` WHERE roleName = ?", new RoleMapper(), roleName);
      
    }

    
    ////////////////////MAPPER\\\\\\\\\\\\\\\\\\\\\\\\\\\
    private static final class RoleMapper implements RowMapper<Role> {

        @Override
        public Role mapRow(ResultSet rs, int rowNumber) throws SQLException {
            Role role = new Role();
            role.setRoleID(rs.getInt("Roleid"));
            role.setRoleType(rs.getString("RoleName"));
            return role;
        }
    }

}