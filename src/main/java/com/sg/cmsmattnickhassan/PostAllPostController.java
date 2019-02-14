/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sg.cmsmattnickhassan;

import com.sg.cmsmattnickhassan.Model.Post;
import com.sg.cmsmattnickhassan.Model.Tag;
import com.sg.cmsmattnickhassan.dao.PostDao;
import com.sg.cmsmattnickhassan.dao.TagDao;
import java.util.List;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.stereotype.Controller;

/**
 *
 * @author nstep
 */

@Controller
public class PostAllPostController {
    
    
    PostDao postDao;
    TagDao tagDao;

    @Inject
    public PostAllPostController(PostDao postDao, TagDao tagDao) {
        this.postDao = postDao;
        this.tagDao = tagDao;
    }
    
    
    
    
    @RequestMapping(value = "/displayPostViewAll", method = RequestMethod.GET)
    public String displayPostAll(Model model) {
        List<Post> postList = postDao.getAllPosts();
        List<Tag> tag =  tagDao.getallTags();
        model.addAttribute("tag", tag);
        //must match items in jsp
        model.addAttribute("postList", postList);
        

        return "postViewAll";
    }
    
}
