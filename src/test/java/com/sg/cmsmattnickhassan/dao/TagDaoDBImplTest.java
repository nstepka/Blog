/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sg.cmsmattnickhassan.dao;

import com.sg.cmsmattnickhassan.Model.Tag;
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
 * @author nstep
 */
public class TagDaoDBImplTest {

    private TagDao dao;
    JdbcTemplate jdbcTemplate = new JdbcTemplate();

    public TagDaoDBImplTest() {
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
        dao = ctx.getBean("TagDao", TagDao.class);

        //delete all Tags to test CRUD
        List<Tag> tag = dao.getallTags();
        for (Tag g : tag) {
            dao.deleteTag(g.getTagid());

        }
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of setJdbcTemplate method, of class TagDaoDBImpl.
     */
    @Test
    public void testSetJdbcTemplate() {
    }

    private Tag addTag() {
        Tag tag = new Tag();
        tag.setTagName("#html");
        return dao.addTag(tag);
    }

    /**
     * Test of addTag method, of class TagDaoDBImpl.
     */
    @Test
    public void testAddTag() {

        Tag tagOne = addTag();
        assertEquals(true, dao.getallTags().contains(tagOne));
        Tag tagTwo = new Tag();
        tagTwo = addTag();
        Tag tagThree = addTag();

        assertEquals(3, dao.getallTags().size());
    }

    /**
     * Test of updateTag method, of class TagDaoDBImpl.
     */
    @Test
    public void testUpdateTag() {

        Tag tagOne = addTag();
        assertEquals(true, dao.getallTags().contains(tagOne));

        String tagName = "#tagupdate";
        tagOne.setTagName(tagName);
        dao.updateTag(tagOne);
        assertEquals(true, dao.getallTags().contains(tagOne));
        Tag tagTwo = dao.getTag(tagOne.getTagid());
        assertEquals(tagName, tagTwo.getTagName());

    }

    /**
     * Test of deleteTag method, of class TagDaoDBImpl.
     */
    @Test
    public void testDeleteTag() {
        Tag tagOne = addTag();
        assertEquals(1, dao.getallTags().size());
        Tag tagTwo = new Tag();
        tagTwo = addTag();
        assertEquals(2, dao.getallTags().size());
        dao.deleteTag(tagOne.getTagid());
        assertEquals(1, dao.getallTags().size());

    }

    /**
     * Test of getTag method, of class TagDaoDBImpl.
     */
    @Test
    public void testGetTag() {
        Tag tagOne = addTag();
        assertEquals(1, dao.getallTags().size());
        Tag tagTwo = new Tag();
        tagTwo = addTag();

        assertEquals(2, dao.getallTags().size());
        int tagID = tagOne.getTagid();
        assertEquals(tagOne, dao.getTag(tagID));

    }

    /**
     * Test of getallTags method, of class TagDaoDBImpl.
     */
    @Test
    public void testGetallTags() {
        Tag tagOne = addTag();
        assertEquals(1, dao.getallTags().size());
        Tag tagTwo = new Tag();
        tagTwo = addTag();
        assertEquals(2, dao.getallTags().size());
        dao.deleteTag(tagTwo.getTagid());
        assertEquals(1, dao.getallTags().size());

    }

}
