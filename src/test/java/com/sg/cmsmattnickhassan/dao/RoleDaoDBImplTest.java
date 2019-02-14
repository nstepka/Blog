/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sg.cmsmattnickhassan.dao;

import com.sg.cmsmattnickhassan.Model.Role;
import java.util.List;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 *
 * @author nstep
 */
public class RoleDaoDBImplTest {
    private RoleDao dao;
    JdbcTemplate jdbcTemplate = new JdbcTemplate();
    
    public RoleDaoDBImplTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
        ApplicationContext ctx
                = new ClassPathXmlApplicationContext("test-applicationContext.xml");
        dao = ctx.getBean("RoleDao", RoleDao.class);

        //delete all Tags to test CRUD
        List<Role> role = dao.getAllRoles();
        for (Role r : role) {
            dao.deleteRole(r.getRoleID());

        }
        
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of setJdbcTemplate method, of class RoleDaoDBImpl.
     */
    @Test
    public void testSetJdbcTemplate() {
    }
    
    private Role addRole() {
        Role role = new Role();
        role.setRoleType("admin");
        return dao.addRole(role);
    }
    
    
    

    /**
     * Test of addRole method, of class RoleDaoDBImpl.
     */
    @Test
    public void testAddRole() {
        
        Role roleOne = addRole();
        assertEquals(true, dao.getAllRoles().contains(roleOne));
        Role roleTwo = new Role();
        roleTwo = addRole();
        Role roleThree = addRole();
        assertEquals(3, dao.getAllRoles().size());
        
    }

    /**
     * Test of updateRole method, of class RoleDaoDBImpl.
     */
    @Test
    public void testUpdateRole() {
        Role roleOne = addRole();
        assertEquals(true, dao.getAllRoles().contains(roleOne));
        String roleType = "user";
        roleOne.setRoleType(roleType);
        dao.updateRole(roleOne);
        assertEquals(true, dao.getAllRoles().contains(roleOne));
        Role roleTwo = dao.getRoleById(roleOne.getRoleID());
        assertEquals(roleType, roleTwo.getRoleType());
    }

    /**
     * Test of deleteRole method, of class RoleDaoDBImpl.
     */
    @Test
    public void testDeleteRole() {
        
        Role roleOne = addRole();
        assertEquals(1, dao.getAllRoles().size());
        Role roleTwo = new Role();
        roleTwo = addRole();
        assertEquals(2, dao.getAllRoles().size());
        dao.deleteRole(roleOne.getRoleID());
        assertEquals(1, dao.getAllRoles().size());
        
    }

    /**
     * Test of getRole method, of class RoleDaoDBImpl.
     */
    @Test
    public void testGetRole() {
        Role roleOne = addRole();
        assertEquals(1, dao.getAllRoles().size());
        Role roleTwo = new Role();
        roleTwo = addRole();
        
        assertEquals(2, dao.getAllRoles().size());
        int roleID = roleOne.getRoleID();
        assertEquals(roleOne, dao.getRoleById(roleID));
        
    }

    /**
     * Test of getAllRoles method, of class RoleDaoDBImpl.
     */
    @Test
    public void testGetAllRoles() {
        Role roleOne = addRole();
        assertEquals(1,dao.getAllRoles().size());
        Role roleTwo = new Role();
        roleTwo = addRole();
        assertEquals(2, dao.getAllRoles().size());
        dao.deleteRole(roleOne.getRoleID());
        assertEquals(1, dao.getAllRoles().size());
       
    }
    
}
