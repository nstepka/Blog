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
import java.util.ArrayList;
import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

/**
 *
 * @author matt_peterson
 */
public class PostDaoDBImpl implements PostDao {

    private JdbcTemplate jdbc;

    public void setJdbcTemplate(JdbcTemplate jdbcTemplate) {
        this.jdbc = jdbcTemplate;
    }

    @Override
    public void addPost(Post post) {
        jdbc.update("INSERT INTO Post "
                + "(PostDate, PostTitle, PostStatus, postContent, Userid) "
                + "VALUES  (?, ?, ?, ?, ?)",
                post.getPostDate().toString(),
                post.getPostTitle(),
                post.getPostStatus(),
                post.getPostContent(),
                post.getUser().getUserID());
        post.setPostid(jdbc.queryForObject("SELECT LAST_INSERT_ID()", Integer.class));
        for (Tag t : post.getTag()) {
            jdbc.update("INSERT INTO PostTag (postID, tagId) VALUES (?, ?)", post.getPostid(), t.getTagid());
        }
    }

    @Override
    public void updatePost(Post post) {
        jdbc.update("UPDATE Post "
                + "SET PostDate = ?, "
                + "PostStatus = ?, "
                + "PostTitle = ?, "
                + "postContent = ?, "
                + "Userid = ? "
                + "WHERE PostID = ?",
                post.getPostDate(),
                post.getPostStatus(),
                post.getPostTitle(),
                post.getPostContent(),
                post.getUser().getUserID(),
                post.getPostid());
        //update the tags
        List<Tag> tagsFromDao = jdbc.query("SELECT Tag.* FROM "
                + "PostTag JOIN Tag ON Tag.TagID = PostTag.tagId WHERE postID = ?",
                new TagMapper(), post.getPostid());

        List<Tag> tagsFromObject = post.getTag();

        //if there is a tag in the object but not the database, add it to the database
        for (Tag t : tagsFromObject) {
            if (!tagsFromDao.contains(t)) {
                jdbc.update("INSERT INTO PostTag (postID, tagId) VALUES (?, ?)",
                        post.getPostid(), t.getTagid());
            }
        }
        for (Tag t : tagsFromDao) {
            if (!tagsFromObject.contains(t)) {
                jdbc.update("DELETE FROM PostTag WHERE postID = ? AND tagId = ?",
                        post.getPostid(), t.getTagid());
            }
        }
    }

    @Override
    public void deletePost(int postId) {
        //gotta delete the post and all entries in postTag that reference it
        jdbc.update("DELETE FROM PostTag WHERE postID = ?", postId);
        jdbc.update("DELETE FROM Post WHERE PostID = ?", postId);
    }

    @Override
    public Post getPost(int postID) {
        Post post = jdbc.queryForObject("SELECT * FROM Post WHERE PostID = ?", new PostMapper(), postID);
        int userId = jdbc.queryForObject("SELECT Userid FROM Post WHERE PostID = ?", Integer.class, postID);
        User u = jdbc.queryForObject("SELECT * FROM `User` WHERE userid = ?", new UserMapper(), userId);
        post.setUser(u);
        List<Tag> taglist = jdbc.query("SELECT * FROM Tag JOIN PostTag ON PostTag.tagId = Tag.TagID WHERE PostID = ?", new TagMapper(), postID);
        post.setTag(taglist);
        return post;
    }

    @Override
    public List<Post> getAllPosts() {
        List<Post> posts = new ArrayList<>();
        List<Integer> postIdsList = jdbc.queryForList("SELECT PostId FROM Post Where PostStatus IS NOT NULL", Integer.class);
        for (int i : postIdsList) {
            posts.add(getPost(i));
        }
        return posts;
    }

    @Override
    public List<Post> getPostByTag(int tagId) {
        List<Integer> postIdsWithSpecifiedTag
                = jdbc.queryForList("SELECT postID FROM PostTag WHERE tagId = ?", Integer.class, tagId);
        List<Post> posts = new ArrayList<>();
        for (int postId : postIdsWithSpecifiedTag) {
            posts.add(getPost(postId));
        }
        return posts;
    }

    @Override
    public List<Post> getPostByUser(int userId) {
        List<Integer> postIdsWithSpecifiedUser
                = jdbc.queryForList("SELECT PostID FROM Post WHERE Userid = ?", Integer.class, userId);
        List<Post> posts = new ArrayList<>();
        for (int postId : postIdsWithSpecifiedUser) {
            posts.add(getPost(postId));
        }
        return posts;
    }

    @Override
    public List<Post> getPostByRole(int roleId) {
        List<Integer> postIdsWithSpecifiedRole
                = jdbc.queryForList("SELECT Post.PostID FROM Post JOIN UserRole ON Post.Userid = UserRole.userID WHERE UserRole.RoleID = ?", Integer.class, roleId);
        List<Post> posts = new ArrayList<>();
        for (int postId : postIdsWithSpecifiedRole) {
            posts.add(getPost(postId));
        }
        return posts;
    }

    private static String SELECT_TAGS_BY_POST
            = "Select * from Tag "
            + "JOIN PostTag on Tag.tagID = PostTag.tagId "
            + "WHERE postID = ?";

    public List<Tag> getAllTagsOfPost(Post p) {
        List<Tag> tagList = jdbc.query(SELECT_TAGS_BY_POST,
                new TagMapper(),
                p.getPostid());

        return tagList;

    }
    
    @Override
    public List<Post> getUnapprovedPosts(){
        List<Post> uPosts;
        uPosts = jdbc.query("SELECT * FROM `Post` WHERE PostStatus IS NULL", new PostMapper(), null);
        for(Post p : uPosts){
            p.setTag(getAllTagsOfPost(p));
            int userId = jdbc.queryForObject("SELECT Userid FROM Post WHERE PostID = ?", Integer.class, p.getPostid());
            User u = jdbc.queryForObject("SELECT * FROM `User` WHERE userid = ?", new UserMapper(), userId);
            p.setUser(u);
        }
        
        return uPosts;
    }

    private static final String SQL_SELECT_10_MOST_RECENT_POST
            = "SELECT * FROM Post  Where PostStatus IS NOT NULL "
            + "ORDER BY PostDate DESC LIMIT 10";

    @Override
    public List<Post> get10MostRecentPost() {
        List<Post> postList = jdbc.query(SQL_SELECT_10_MOST_RECENT_POST,
                new PostMapper());
        for (Post p : postList) {
            p.setTag(getAllTagsOfPost(p));

            int userId = jdbc.queryForObject("SELECT Userid FROM Post WHERE PostID = ?", Integer.class, p.getPostid());
            User u = jdbc.queryForObject("SELECT * FROM `User` WHERE userid = ?", new UserMapper(), userId);
            p.setUser(u);

        }
        return postList;
    }

    private static final class PostMapper implements RowMapper<Post> {

        @Override
        public Post mapRow(ResultSet rs, int i) throws SQLException {
            Post post = new Post();
            post.setPostid(rs.getInt("PostID"));
            post.setPostDate(rs.getTimestamp("postDate").
                    toLocalDateTime().toLocalDate());
            post.setPostTitle(rs.getString("PostTitle"));
            post.setPostStatus(rs.getString("PostStatus"));
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
