/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sg.cmsmattnickhassan.dao;

import com.sg.cmsmattnickhassan.Model.Post;
import com.sg.cmsmattnickhassan.Model.Tag;
import com.sg.cmsmattnickhassan.Model.User;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.LocalDate;
import java.time.Month;
import java.util.ArrayList;
import java.util.List;
import org.junit.After;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

/**
 *
 * @author mpete
 */
public class PostDaoDBImplTest {

    private PostDao dao;
    private JdbcTemplate jdbc;
    private String sqlScript = "CMS_TEST.xml";

    public PostDaoDBImplTest() {
    }


    @Before
    public void setUp() {
        ApplicationContext ctx = new ClassPathXmlApplicationContext("test-applicationContext.xml");
        dao = ctx.getBean("PostDao", PostDao.class);
        jdbc = ctx.getBean("jdbcTemplate", JdbcTemplate.class);
    }

    @After
    public void tearDown() {
        jdbc.update("DELETE FROM UserRole");
        jdbc.update("DELETE FROM PostTag");
        jdbc.update("DELETE FROM Tag");
        jdbc.update("DELETE FROM Post");
        jdbc.update("DELETE FROM `Role`");
        jdbc.update("DELETE FROM `User`");
    }
    

    @Test
    public void testAddGetPost() {
        Post p = new Post();
        p.setPostContent("kjsldkjflkwejlkjwlekjlwkjelkjwdlkewjckjewoijzkdjwliejlkcj");
        p.setPostDate(LocalDate.now());
        p.setPostStatus("unread");
        User u = new User();
        u.setUserID(1);
        u.setUserName("user1");
        p.setUser(u);
        jdbc.update("INSERT INTO `User` ( userName ) VALUES ( ? )","user1" );
        u.setUserID(jdbc.queryForObject("SELECT LAST_INSERT_ID()", Integer.class));
        jdbc.update("INSERT INTO Tag (TagName) VALUES ('#Lorem')");
        Tag t = new Tag();
        t.setTagName("#Lorem");
        t.setTagid(jdbc.queryForObject("SELECT LAST_INSERT_ID()", Integer.class));
        List<Tag> tags = new ArrayList<>();
        tags.add(t);
        p.setTag(tags);
        
        dao.addPost(p);
        Post pFromDao = dao.getPost(p.getPostid());
        assertEquals(pFromDao, p);
        
    }

    @Test
    public void testUpdatePost() {
        Post p = new Post();
        p.setPostContent("kjsldkjflkwejlkjwlekjlwkjelkjwdlkewjckjewoijzkdjwliejlkcj");
        p.setPostDate(LocalDate.now());
        p.setPostStatus("unread");
        User u = new User();
        u.setUserID(1);
        u.setUserName("user1");
        p.setUser(u);
        jdbc.update("INSERT INTO `User` ( userName ) VALUES ( ? )","user1" );
        u.setUserID(jdbc.queryForObject("SELECT LAST_INSERT_ID()", Integer.class));
        jdbc.update("INSERT INTO Tag (TagName) VALUES ('#Lorem')");
        Tag t = new Tag();
        t.setTagName("#Lorem");
        t.setTagid(jdbc.queryForObject("SELECT LAST_INSERT_ID()", Integer.class));
        List<Tag> tags = new ArrayList<>();
        tags.add(t);
        p.setTag(tags);
        dao.addPost(p);
        p.setPostContent("ksdhfwkjemmmejkesuuuewkjd");
        Post pFromDao = dao.getPost(p.getPostid());
        assertFalse(pFromDao.equals(p));
        dao.updatePost(p);
        pFromDao = dao.getPost(p.getPostid());
        assertEquals(p, pFromDao);
    }

    @Test
    public void testDeletePost() {
        Post p = new Post();
        p.setPostContent("kjsldkjflkwejlkjwlekjlwkjelkjwdlkewjckjewoijzkdjwliejlkcj");
        p.setPostDate(LocalDate.now());
        p.setPostStatus("unread");
        User u = new User();
        u.setUserID(1);
        u.setUserName("user1");
        p.setUser(u);
        jdbc.update("INSERT INTO `User` ( userName ) VALUES ( ? )","user1" );
        u.setUserID(jdbc.queryForObject("SELECT LAST_INSERT_ID()", Integer.class));
        jdbc.update("INSERT INTO Tag (TagName) VALUES ('#Lorem')");
        Tag t = new Tag();
        t.setTagName("#Lorem");
        t.setTagid(jdbc.queryForObject("SELECT LAST_INSERT_ID()", Integer.class));
        List<Tag> tags = new ArrayList<>();
        tags.add(t);
        p.setTag(tags);
        dao.addPost(p);
        
        assertTrue(dao.getAllPosts().contains(p));
        dao.deletePost(p.getPostid());
        assertFalse(dao.getAllPosts().contains(p));
    }

    @Test
    public void testGetPostByTag() {
        Post p1 = new Post();
        p1.setPostContent("kjsldkjflkwejlkjwlekjlwkjelkjwdlkewjckjewoijzkdjwliejlkcj");
        p1.setPostDate(LocalDate.now());
        p1.setPostStatus("unread");
        Post p2 = new Post();
        p2.setPostContent("lkskkjejwnklendekekekeke");
        p2.setPostDate(LocalDate.now());
        p2.setPostStatus("unread");
        Post p3 = new Post();
        p3.setPostContent("lkskkjejwnklendekeklkkkkkkekeke");
        p3.setPostDate(LocalDate.now());
        p3.setPostStatus("unread");
        
        
        User u = new User();
        u.setUserID(1);
        u.setUserName("user1");
        p1.setUser(u);
        p2.setUser(u);
        p3.setUser(u);
        jdbc.update("INSERT INTO `User` ( userName ) VALUES ( ? )","user1" );
        u.setUserID(jdbc.queryForObject("SELECT LAST_INSERT_ID()", Integer.class));
        jdbc.update("INSERT INTO Tag (TagName) VALUES ('#Lorem')");
        Tag t = new Tag();
        t.setTagName("#Lorem");
        t.setTagid(jdbc.queryForObject("SELECT LAST_INSERT_ID()", Integer.class));
        List<Tag> tags = new ArrayList<>();
        tags.add(t);
        
        Tag t2 = new Tag();
        jdbc.update("INSERT INTO Tag (TagName) VALUES ('#Ipsum')");
        t2.setTagName("#Ipsum");
        t2.setTagid(jdbc.queryForObject("SELECT LAST_INSERT_ID()", Integer.class));
        List<Tag> altTags = new ArrayList<>();
        altTags.add(t);
        altTags.add(t2);
        
        p1.setTag(tags);
        p2.setTag(tags);
        p3.setTag(altTags);
        dao.addPost(p1);
        dao.addPost(p2);
        dao.addPost(p3);
        
        List<Post> postsWithTag1 = dao.getPostByTag(t.getTagid());
        List<Post> postsWithTag2 = dao.getPostByTag(t2.getTagid());
        
        assertTrue(postsWithTag1.contains(p1));
        assertTrue(postsWithTag1.contains(p2));
        assertTrue(postsWithTag1.contains(p3));
        
        assertFalse(postsWithTag2.contains(p1));
        assertFalse(postsWithTag2.contains(p2));
        assertTrue(postsWithTag2.contains(p3));
    }

    @Test
    public void testGetPostByUser() {
        Post p1 = new Post();
        p1.setPostContent("kjsldkjflkwejlkjwlekjlwkjelkjwdlkewjckjewoijzkdjwliejlkcj");
        p1.setPostDate(LocalDate.now());
        p1.setPostStatus("unread");
        Post p2 = new Post();
        p2.setPostContent("lkskkjejwnklendekekekeke");
        p2.setPostDate(LocalDate.of(2018, Month.MARCH, 6));
        p2.setPostStatus("unread");
        Post p3 = new Post();
        p3.setPostContent("lkskkjejwnklendekeklkkkkkkekeke");
        p3.setPostDate(LocalDate.of(2018, Month.MARCH, 9));
        p3.setPostStatus("unread");
        
        
        User u = new User();
        u.setUserID(1);
        u.setUserName("user1");
        p1.setUser(u);
        p2.setUser(u);
        p3.setUser(u);
        jdbc.update("INSERT INTO `User` ( userName ) VALUES ( ? )","user1" );
        u.setUserID(jdbc.queryForObject("SELECT LAST_INSERT_ID()", Integer.class));
        jdbc.update("INSERT INTO Tag (TagName) VALUES ('#Lorem')");
        Tag t = new Tag();
        t.setTagName("#Lorem");
        t.setTagid(jdbc.queryForObject("SELECT LAST_INSERT_ID()", Integer.class));
        List<Tag> tags = new ArrayList<>();
        tags.add(t);
        
        Tag t2 = new Tag();
        jdbc.update("INSERT INTO Tag (TagName) VALUES ('#Ipsum')");
        t2.setTagName("#Ipsum");
        t2.setTagid(jdbc.queryForObject("SELECT LAST_INSERT_ID()", Integer.class));
        List<Tag> altTags = new ArrayList<>();
        altTags.add(t);
        altTags.add(t2);
        
        p1.setTag(tags);
        p2.setTag(tags);
        p3.setTag(altTags);
        dao.addPost(p1);
        dao.addPost(p2);
        dao.addPost(p3);
    }

    @Test
    public void testGetPostByRole() {
    }

    private static final class PostMapper implements RowMapper<Post> {

        @Override
        public Post mapRow(ResultSet rs, int i) throws SQLException {
            Post post = new Post();
            post.setPostid(rs.getInt("postId"));
            post.setPostDate(rs.getTimestamp("postDate").toLocalDateTime().toLocalDate());
            post.setPostStatus(rs.getString("postStatus"));
            post.setPostContent(rs.getString("postContent"));
            return post;
        }
    }

    private static final class UserMapper implements RowMapper<User> {

        @Override
        public User mapRow(ResultSet rs, int i) throws SQLException {
            User user = new User();
            user.setUserID(rs.getInt("userid"));
            user.setUserName(rs.getString("userName"));
            return user;
        }
    }

    private static final class TagMapper implements RowMapper<Tag> {

        @Override
        public Tag mapRow(ResultSet rs, int i) throws SQLException {
            Tag tag = new Tag();
            tag.setTagid(rs.getInt("TagID"));
            tag.setTagName(rs.getString("TagName"));
            return tag;
        }
    }

}
