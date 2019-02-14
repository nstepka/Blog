/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sg.cmsmattnickhassan;

import com.sg.cmsmattnickhassan.Model.Post;
import com.sg.cmsmattnickhassan.Model.Tag;
import com.sg.cmsmattnickhassan.Model.User;
import com.sg.cmsmattnickhassan.dao.PostDao;
import com.sg.cmsmattnickhassan.dao.TagDao;
import com.sg.cmsmattnickhassan.dao.UserDao;
import java.security.Principal;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import javax.inject.Inject;
import org.springframework.stereotype.Controller;
import javax.servlet.http.HttpServletRequest;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 *
 * @author nstep
 */
@Controller
public class PostApprovalController {

    PostDao postDao;

    @Inject
    public PostApprovalController(PostDao postDao) {
        this.postDao = postDao;
    }

    @RequestMapping(value = "/displayPostApprovalPage", method = RequestMethod.GET)
    public String displayPostApproval(Model model) {
        List<Post> postList = postDao.getUnapprovedPosts();
        //must match items in jsp
        model.addAttribute("postList", postList);
        

        return "postApproval";
    }
    
    @RequestMapping(value = "/postApproval", method = RequestMethod.GET)
    public String approvePost(HttpServletRequest request) {
        // grab the incoming values from the form and create a new Contact
        // object
        String postIDParameter = request.getParameter("postid");
        int postID = Integer.parseInt(postIDParameter);
        Post post = postDao.getPost(postID);
        post.setPostStatus("Approved");
        postDao.updatePost(post);
        
        // we don't want to forward to a View component - we want to
        // redirect to the endpoint that displays the Approval Page
        // so it can display the new Contact in the table.
        return "redirect:displayPostApprovalPage";
    
    
    }
    
    
    @RequestMapping(value = "/displayPostDetail", method = RequestMethod.GET)
    public String displayPostDetail(HttpServletRequest request, Model model) {
        String postIDParameter = request.getParameter("postid");
        int postID = Integer.parseInt(postIDParameter);
        Post post = postDao.getPost(postID);

        model.addAttribute("post", post);

        return "postDetail";
    }

}
