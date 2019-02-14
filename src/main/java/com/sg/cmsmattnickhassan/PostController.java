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


@Controller
public class PostController {

    PostDao postDao;
    TagDao tagDao;
    UserDao userDao;

    @Inject
    public PostController(PostDao postDao, TagDao tagDao, UserDao userDao) {
        this.postDao = postDao;
        this.tagDao = tagDao;
        this.userDao= userDao;
    }
    
    

    
    
    
    @RequestMapping(value = "/displayCreatePost", method = RequestMethod.GET)
    public String displayCreatePostPage(Model model) {
        List<Post> posts = postDao.getAllPosts();
        List<Tag> tags = tagDao.getallTags();
        
        //must match items in jsp
        model.addAttribute("tags", tags);
        model.addAttribute("posts", posts);
        
        return "CreatePost";
    }
    
//    @RequestMapping(value = "/displayPostView", method = RequestMethod.GET)
//    public String displayAllPostDetails(HttpServletRequest request, Model model) {
//        String postIDParameter = request.getParameter("sightingID");
//        int postID = Integer.parseInt(postIDParameter);
//        Post post = postDao.getPost(postID);
//        model.addAttribute("post", post);
//
//        return "postView";
//    }
    
    @RequestMapping(value = "/displayPostView", method = RequestMethod.GET)
    public String displayPostPage(Model model) {
        List<Post> postList = postDao.getAllPosts();
        model.addAttribute("postList", postList);
        
        return "postView";
    }
    //NEED TO DO postStatus and post date
    @RequestMapping(value = "/createPost", method = RequestMethod.POST)
    public String createPost(Principal principal, HttpServletRequest request, Model model) {
        Post post = new Post();
        post.setPostContent(request.getParameter("userPost"));
        post.setPostTitle(request.getParameter("title"));
        
        String[] stringTags = request.getParameterValues("tagPost");

        // we need a splitter for tags.
        List<Tag> tags = new ArrayList<>();
        for (String oneTag : stringTags) {
            int tagID = Integer.parseInt(oneTag);
            tags.add(tagDao.getTag(tagID));

        }
        
        post.setTag(tags);
        LocalDate date = LocalDate.now();
        post.setPostDate(date);
        // int userID = 0;
        // userID = Integer.parseInt(request.getParameter("userID"));
        
        User user = userDao.getUserByUsername(principal.getName());
        post.setUser(user);
        post.setTag(tags);
        postDao.addPost(post);
       
        model.addAttribute("user", user);
        model.addAttribute("tags", tags);
        model.addAttribute("post", post);
        return "redirect:displayCreatePost";
    }
    
   
    
    @RequestMapping(value = "/deletePost", method = RequestMethod.GET)
    public String deletePost(HttpServletRequest request) {
        String postIDParameter = request.getParameter("postid");
        int postID = Integer.parseInt(postIDParameter);
        postDao.deletePost(postID);
        return "redirect:displayPostView";
    }

}
