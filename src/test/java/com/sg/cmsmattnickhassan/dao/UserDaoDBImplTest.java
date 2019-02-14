/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sg.cmsmattnickhassan.dao;

import com.sg.cmsmattnickhassan.Model.Tag;
import com.sg.cmsmattnickhassan.Model.User;
import java.util.List;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 *
 * @author hassan
 */
public class UserDaoDBImplTest {

    private UserDao dao;
    JdbcTemplate jdbcTemplate = new JdbcTemplate();

    public UserDaoDBImplTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

//    @Before
//    public void setUp() {
//        ApplicationContext ctx
//                = new ClassPathXmlApplicationContext("test-applicationContext.xml");
//        dao = ctx.getBean("UserDao", UserDao.class);
//
//        //delete all Users to test CRUD
//        List<User> user = dao.getAllUsers();
//        for (User s : user) {
//            dao.delete(s.getUserID());
//
//        }
//    }
//
//    @After
//    public void tearDown() {
//    }
//
//    /**
//     * Test of setJdbcTemplate method, of class TagDaoDBImpl.
//     */
//    @Test
//    public void testSetJdbcTemplate() {
//    }
//
//    public void addUser() {
//        User user = new User();
//        user.setUserName("xasan");
//        dao.addUser(user);
//
//    }
//
//    /**
//     * Test of addTag method, of class UserDaoDBImpl.
//     */
//    @Test
//    public void testAddUser() {
//
//        User userOne = new User();
//        userOne.setUserName("xasan");
//        dao.addUser(userOne);
//        
//        User user2 = new User();
//        user2.setUserName("cali");
//        dao.addUser(user2);
//        
//        User fromDao = dao.getUser(user2.getUserID());
//        assertEquals(2, fromDao);
//        
//    }
//
//    /**
//     * Test of updateTag method, of class TagDaoDBImpl.
//     */
//    @Test
//    public void testUpdateTag() {
//
//        Tag tagOne = addTag();
//        assertEquals(true, dao.getallTags().contains(tagOne));
//
//        String tagName = "#tagupdate";
//        tagOne.setTagName(tagName);
//        dao.updateTag(tagOne);
//        assertEquals(true, dao.getallTags().contains(tagOne));
//        Tag tagTwo = dao.getTag(tagOne.getTagid());
//        assertEquals(tagName, tagTwo.getTagName());
//
//    }
//
//    /**
//     * Test of deleteTag method, of class TagDaoDBImpl.
//     */
//    @Test
//    public void testDeleteTag() {
//        Tag tagOne = addTag();
//        assertEquals(1, dao.getallTags().size());
//        Tag tagTwo = new Tag();
//        tagTwo = addTag();
//        assertEquals(2, dao.getallTags().size());
//        dao.deleteTag(tagOne.getTagid());
//        assertEquals(1, dao.getallTags().size());
//
//    }
//
//    /**
//     * Test of getTag method, of class TagDaoDBImpl.
//     */
//    @Test
//    public void testGetTag() {
//        Tag tagOne = addTag();
//        assertEquals(1, dao.getallTags().size());
//        Tag tagTwo = new Tag();
//        tagTwo = addTag();
//
//        assertEquals(2, dao.getallTags().size());
//        int tagID = tagOne.getTagid();
//        assertEquals(tagOne, dao.getTag(tagID));
//
//    }
//
//    /**
//     * Test of getallTags method, of class TagDaoDBImpl.
//     */
//    @Test
//    public void testGetallTags() {
//        Tag tagOne = addTag();
//        assertEquals(1, dao.getallTags().size());
//        Tag tagTwo = new Tag();
//        tagTwo = addTag();
//        assertEquals(2, dao.getallTags().size());
//        dao.deleteTag(tagTwo.getTagid());
//        assertEquals(1, dao.getallTags().size());
//
//    }
//
}
