/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sg.cmsmattnickhassan.dao;

import com.sg.cmsmattnickhassan.Model.Tag;
import java.util.List;

/**
 *
 * @author hassan
 */
public interface TagDao {
    
    
    
    
    public Tag addTag(Tag tag);
    public Tag updateTag(Tag tag);
    public void deleteTag(int tagid);
    public Tag getTag(int tagid);
    public List<Tag> getallTags();
    
    

}
