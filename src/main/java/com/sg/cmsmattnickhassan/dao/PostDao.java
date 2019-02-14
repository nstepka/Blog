/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sg.cmsmattnickhassan.dao;

import com.sg.cmsmattnickhassan.Model.Post;
import java.util.List;

/**
 *
 * @author hassan
 */
public interface PostDao {
    
    public void addPost(Post post);
    public void updatePost(Post post);
    public void deletePost(int postId);
    public Post getPost(int postID);
    public List<Post> getAllPosts();
    
    public List<Post> getPostByTag(int tagId);
    public List<Post> getPostByUser(int userId);
    public List<Post> getPostByRole(int roleId);
    public List<Post> getUnapprovedPosts();
    public List<Post> get10MostRecentPost();
    
    
}
