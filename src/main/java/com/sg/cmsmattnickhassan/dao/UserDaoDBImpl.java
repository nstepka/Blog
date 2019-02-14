/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sg.cmsmattnickhassan.dao;

import com.sg.cmsmattnickhassan.Model.Role;
import com.sg.cmsmattnickhassan.Model.User;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.transaction.annotation.Transactional;

/**
 *
 * @author hassan
 */
public class UserDaoDBImpl implements UserDao {

    private JdbcTemplate jdbc;

    public void setJdbcTemplate(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    private static final String SQL_INSERT_USER
            = "INSERT INTO User "
            + "(userName, userPassword, enabled) "
            + "values(?, ?, ?)";

    @Override
    @Transactional
    public User addUser(User user) {
        if (getUserByUsername(user.getUserName()) == null) {

            jdbc.update(SQL_INSERT_USER,
                    user.getUserName(), user.getPassword(), user.isEnabled());
            user.setUserID(jdbc.queryForObject("select LAST_INSERT_ID()",
                    Integer.class));
            List<Role> roles = user.getRoles();
            for (Role r : roles) {
                jdbc.update("INSERT INTO UserRole ( userID, RoleID ) VALUES ( ?, ?) ", user.getUserID(), r.getRoleID());
            }
        }
        return user;
    }

    private static final String SQL_UPDATE_USER
            = "update User set userName = ?, userPassword = ?, enabled = ? where userID = ? ";

    @Override
    @Transactional
    public User updateUser(User user) {
        jdbc.update(SQL_UPDATE_USER,
                user.getUserName(), user.getPassword(), user.isEnabled(), user.getUserID());
        List<Role> roles = user.getRoles();
        jdbc.update("DELETE FROM UserRole WHERE userID = ?", user.getUserID());
        for (Role r : roles) {
            jdbc.update("INSERT INTO UserRole ( userID, RoleID ) VALUES ( ?, ?) ", user.getUserID(), r.getRoleID());
        }
        return user;
    }

    private static final String SQL_DELETE_USER
            = "delete from User where userID =  ?";

    private static final String SQL_DELETE_USERPOST
            = "delete from Post where userID = ?";

    @Override
    public void deleteUser(int userID) {
        jdbc.update("DELETE FROM UserRole WHERE userID = ?", userID);
        
        jdbc.update(SQL_DELETE_USERPOST, userID);
        jdbc.update(SQL_DELETE_USER, userID);
    }

    private static final String SELECT_ROLES_BY_USERID
            = "SELECT * FROM `Role` JOIN UserRole ON `Role`.roleId = UserRole.roleId WHERE UserRole.userId = ?";

    private List<Role> insertUserRole(User user) {

        List<Role> roles = jdbc.query(SELECT_ROLES_BY_USERID,
                new RoleMapper(), user.getUserID());
        return roles;
    }

    private static final String SQL_SELECT_USER
            = "select * from User where userID = ?";

    @Override
    public User getUserById(int userID) {
        try {
            User user = jdbc.queryForObject(SQL_SELECT_USER,
                    new UserMapper(), userID);
            user.setRoles(insertUserRole(user));
            return user;
        } catch (EmptyResultDataAccessException ex) {
            // there were no results for the given contact id - we just 
            // want to return null in this case
            return null;
        }

    }

    private static final String SQL_SELECT_ALL_USERS
            = "select * from User";

    @Override
    public List<User> getAllUsers() {
        List<User> u = jdbc.query(SQL_SELECT_ALL_USERS, new UserMapper());
        for (User user : u) {
            user.setRoles(insertUserRole(user));
        }
        return u;

    }

    private static final String SQL_SELECT_USER_ROLE
            = "select u.userid, u.userName from User u "
            + "join UserRole ur on a u.userid = ur.userid where ur.roleid = ?";

    private List<User> findUsersforRole(User user) {
        return jdbc.query(SQL_SELECT_USER_ROLE, new UserMapper(), user.getUserID());

    }

    private static final String SELECT_ALL_USERS_BY_ROLE_ID
            = "select * from User u "
            + "join UserRole ur on u.userid = ur.userID "
            + "where ur.RoleID = ?";

    //get all user by role id
    @Override
    public List<User> getUserRole(int roleID) {
        List<User> userList = jdbc.query(SQL_SELECT_USER_ROLE, new UserMapper(),
                roleID);
        return userList;
    }

    @Override
    public User getUserByUsername(String username) {
        
        try{
            int userId = jdbc.queryForObject("SELECT userid FROM `User` WHERE userName = ?", Integer.class, username);
            return getUserById(userId);
        } catch (EmptyResultDataAccessException ex) {
            return null;
        }
    }

    private static final class UserMapper implements RowMapper<User> {

        @Override
        public User mapRow(ResultSet rs, int rowNumber) throws SQLException {
            User user = new User();
            user.setUserID(rs.getInt("userid"));
            user.setUserName(rs.getString("UserName"));
            user.setPassword(rs.getString("userPassword"));
            user.setEnabled(rs.getBoolean("enabled"));
            return user;
        }

    }

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
