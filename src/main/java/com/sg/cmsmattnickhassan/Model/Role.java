/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.sg.cmsmattnickhassan.Model;

import java.util.Objects;

/**
 *
 * @author hassan
 */
public class Role {
    private int roleID;
    private String roleType;

    public int getRoleID() {
        return roleID;
    }

    public void setRoleID(int roleID) {
        this.roleID = roleID;
    }

    public String getRoleType() {
        return roleType;
    }

    public void setRoleType(String roleType) {
        this.roleType = roleType;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 31 * hash + this.roleID;
        hash = 31 * hash + Objects.hashCode(this.roleType);
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
        final Role other = (Role) obj;
        if (this.roleID != other.roleID) {
            return false;
        }
        if (!Objects.equals(this.roleType, other.roleType)) {
            return false;
        }
        return true;
    }

    
}
