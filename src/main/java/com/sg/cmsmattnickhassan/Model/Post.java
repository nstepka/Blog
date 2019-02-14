/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sg.cmsmattnickhassan.Model;

import java.time.LocalDate;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 *
 * @author hassan
 */
public class Post {
    private int postid;
    private LocalDate postDate;
    private String postStatus;
    private String postContent;
    private String postTitle;
    private User User;
    private List<Tag> tag;

    public int getPostid() {
        return postid;
    }

    public void setPostid(int postid) {
        this.postid = postid;
    }

    public LocalDate getPostDate() {
        return postDate;
    }

    public void setPostDate(LocalDate postDate) {
        this.postDate = postDate;
    }

    public String getPostStatus() {
        return postStatus;
    }

    public void setPostStatus(String postStatus) {
        this.postStatus = postStatus;
    }

    public String getPostContent() {
        return postContent;
    }

    public void setPostContent(String postContent) {
        this.postContent = postContent;
    }

    public User getUser() {
        return User;
    }

    public void setUser(User User) {
        this.User = User;
    }

    public List<Tag> getTag() {
        return tag;
    }

    public void setTag(List<Tag> tag) {
        this.tag = tag;
    }
    
    

    public String getPostTitle() {
        return postTitle;
    }

    public void setPostTitle(String postTitle) {
        this.postTitle = postTitle;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 23 * hash + this.postid;
        hash = 23 * hash + Objects.hashCode(this.postDate);
        hash = 23 * hash + Objects.hashCode(this.postStatus);
        hash = 23 * hash + Objects.hashCode(this.postContent);
        hash = 23 * hash + Objects.hashCode(this.postTitle);
        hash = 23 * hash + Objects.hashCode(this.User);
        hash = 23 * hash + Objects.hashCode(this.tag);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Post other = (Post) obj;
        if (this.postid != other.postid) {
            return false;
        }
        if (!Objects.equals(this.postStatus, other.postStatus)) {
            return false;
        }
        if (!Objects.equals(this.postContent, other.postContent)) {
            return false;
        }
        if (!Objects.equals(this.postTitle, other.postTitle)) {
            return false;
        }
        if (!Objects.equals(this.postDate, other.postDate)) {
            return false;
        }
        if (!Objects.equals(this.User, other.User)) {
            return false;
        }
        if (!Objects.equals(this.tag, other.tag)) {
            return false;
        }
        return true;
    }

   
}