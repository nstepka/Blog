/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sg.cmsmattnickhassan.dao;

import com.sg.cmsmattnickhassan.Model.Role;
import com.sg.cmsmattnickhassan.Model.Tag;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.transaction.annotation.Transactional;

/**
 *
 * @author hassan
 */
public class TagDaoDBImpl implements TagDao{
    
    
    private JdbcTemplate jdbc;

    public void setJdbcTemplate(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }
    
    private static final String SQL_INSERT_TAG
            = "INSERT INTO Tag "
            + "(TagName) "
            + "values (?)";
    
    
    @Override
    @Transactional
    public Tag addTag(Tag tag) {
        jdbc.update(SQL_INSERT_TAG, tag.getTagName());
        tag.setTagid(jdbc.queryForObject("select LAST_INSERT_ID()",
                Integer.class));
        return tag;
    }

    
    private static final String SQL_UPDATE_TAG
            = "UPDATE Tag "
            + "SET TagName = ? "
            + "WHERE TagID = ?";
    
    
    @Override
    @Transactional
    public Tag updateTag(Tag tag) {
        jdbc.update(SQL_UPDATE_TAG, tag.getTagName(), tag.getTagid());
        
        return tag;
    }
    
    
    private static final String SQL_DELETE_TAG
            = "DELETE FROM Tag "
            + "WHERE TagID = ?";
    
    private static final String SQL_DELETE_TAG_FROM_POSTTAG
           = "DELETE FROM posttag "
            + "where tagId = ?";
    
    @Override
    @Transactional
    public void deleteTag(int tagid) {
     jdbc.update(SQL_DELETE_TAG_FROM_POSTTAG, tagid);
     jdbc.update(SQL_DELETE_TAG, tagid);
     
    
    }
    
    private static String SQL_GET_TAG
            = "SELECT * FROM Tag "
            + "WHERE TagID = ?";

    @Override
    @Transactional        
    public Tag getTag(int tagid) {
        try {
            return jdbc.queryForObject(SQL_GET_TAG,
                    new TagMapper(), tagid);
        } catch (EmptyResultDataAccessException ex) {
            // there were no results for the given contact id - we just 
            // want to return null in this case
            return null;
        }
    }

    private static final String SQL_GET_ALL_TAG
            = "SELECT * FROM Tag";
    
    
    @Override
    public List<Tag> getallTags() {
        return jdbc.query(SQL_GET_ALL_TAG, new TagMapper());
        
    
    }
    
    private static final class TagMapper implements RowMapper<Tag> {

        @Override
        public Tag mapRow(ResultSet rs, int rowNumber) throws SQLException {
            Tag tag = new Tag();
            tag.setTagid(rs.getInt("TagID"));
            tag.setTagName(rs.getString("TagName"));
            return tag;
        }
    }

}
