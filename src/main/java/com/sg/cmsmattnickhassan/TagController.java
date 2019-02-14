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
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 *
 * @author nstep
 */
@Controller
public class TagController {
   TagDao tagDao;
   PostDao postDao;
   
   @Inject
   public TagController(TagDao tagDao, PostDao postDao) {
       this.tagDao = tagDao;
       this.postDao = postDao;
   }
   
   
   @RequestMapping(value = "/displayCreateTagPage", method = RequestMethod.GET)
    public String displayCreateTagPage(Model model) {
        List<Tag> tagList = tagDao.getallTags();
        model.addAttribute("tagList", tagList);
        
        return "CreateTag";
    }
    
    @RequestMapping(value = "/CreateTag", method = RequestMethod.POST)
    public String createTag(HttpServletRequest request) {
        // grab the incoming values from the form and create a new Contact
        // object
        Tag tag = new Tag();
        
        tag.setTagName(request.getParameter("tagName"));
        tag = tagDao.addTag(tag);

        // we don't want to forward to a View component - we want to
        // redirect to the endpoint that displays the Contacts Page
        // so it can display the new Contact in the table.
        return "redirect:displayCreateTagPage";
    
    
    }
    
    @RequestMapping(value = "/displayTagDetails", method = RequestMethod.GET)
    public String displayTagDetails(HttpServletRequest request, Model model) {
        String tagIDParameter = request.getParameter("tagID");
        int tagID = Integer.parseInt(tagIDParameter);
        Tag tag = tagDao.getTag(tagID);
        List<Post> post = postDao.getPostByTag(tagID);
        model.addAttribute("post", post);
        model.addAttribute("tag", tag);

        return "tagDetails";
    }
    
    
    @RequestMapping(value = "/deleteTag", method = RequestMethod.GET)
    public String deleteTag(HttpServletRequest request) {
        String tagIDParameter = request.getParameter("tagid");
        int tagID = Integer.parseInt(tagIDParameter);
        tagDao.deleteTag(tagID);
        return "redirect:displayCreateTagPage";
    }
    
    
    
    
    
   
   
}
