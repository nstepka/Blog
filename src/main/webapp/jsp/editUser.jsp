<%-- 
    Document   : editUser
    Created on : Oct 30, 2018, 3:00:31 PM
    Author     : mpete
--%>

<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="s" uri="http://www.springframework.org/tags"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
    <head>
        <title>Add and Remove Users</title>
        <!-- Bootstrap core CSS -->
        <link href="${pageContext.request.contextPath}/css/bootstrap.min.css" rel="stylesheet">        
    </head>
    <body>
        <div class="container">
            <h1>Hello Security</h1>
            <hr/>
            <h2>Edit User Page</h2>
            <h2>Admin Page</h2>
            <hr/>
            <div class="navbar">
                <ul class="nav nav-tabs">
                    <li role="presentation">
                        <a href="${pageContext.request.contextPath}/">
                            Home Page
                        </a>
                    </li>
                    <li role="presentation" class="active">
                        <a href="${pageContext.request.contextPath}/displayCreateTagPage">
                            Create Tag
                        </a>
                    </li>
                    <li role="presentation">
                        <a href="${pageContext.request.contextPath}/displayCreatePost">
                            Create Post
                        </a>
                    </li>
                    
                    <li role="presentation">
                        <a href="${pageContext.request.contextPath}/displayPostApprovalPage">
                            Approve Post
                        </a>
                    </li>
                    <li role="presentation">
                        <a href="${pageContext.request.contextPath}/displayPostView">
                            List Post
                        </a>
                    </li>
                </ul>    
            </div>
            <sec:authorize access="isAuthenticated()">
                <form class="form-inline" 
                      method="POST" 
                      action="${pageContext.request.contextPath}/logout">
                    <input type="hidden" 
                           name="${_csrf.parameterName}" 
                           value="${_csrf.token}"/>
                    <label for="submit">
                        Hello : ${pageContext.request.userPrincipal.name}&nbsp;&nbsp;&nbsp;|
                    </label>
                    <button class="btn btn-link" id="submit" type="submit">Logout</button>
                </form>
            </sec:authorize>
            <p>
            <div class="container">
                <div class="row">
                    <h3>Update User</h3>
                    <form method="POST" action="${pageContext.request.contextPath}/editUser">
                        <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
                        <input type="hidden" name="id" value ="${user.getUserID()}"/>
                        <div class="form-group">
                            <label for="username" class="col-md-4 control-label">Username:</label>
                            <div class="col-md-8">
                                <input type="text" 
                                       class="form-control" 
                                       id="username"
                                       name="username" 
                                       placeholder="Username"
                                       value="${user.getUserName()}"
                                       disabled/>
                            </div>
                        </div>
                                   
                        <div class="form-group">
                            <label for="roleIdList" class="col-md-4 control-label">Roles:</label>
                            <div class="col-md-8">
                                <select id="roleIdList" 
                                        name="roleIdList" 
                                        multiple="multiple" 
                                        class="form-control">
                                    <c:forEach items="${roles}" var="currentRole">
                                        <option value="${currentRole.getRoleID()}" 
                                                <c:if test="${user.getRoles().contains(currentRole)}">selected</c:if>>
                                            <c:out value="${currentRole.getRoleType()}"/>
                                        </option>
                                    </c:forEach>
                                </select>
                            </div>
                        </div>
                        <div class="form-group">
                            <div class="col-md-offset-4 col-md-8">
                                <input type="submit" 
                                       class="btn btn-default" 
                                       id="search-button" 
                                       value="Update User"/>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
            <div class="container">
                <div class="row">
                    <h3>Update Password</h3>
                    <c:if test="${error != null}">
                        <div class="alert alert-danger" role="alert">
                            <c:out value="${error}"/>
                        </div>
                    </c:if>
                    <form method="POST" 
                          action="${pageContext.request.contextPath}/editPassword">
                        <input type="hidden" 
                               name="${_csrf.parameterName}" 
                               value="${_csrf.token}"/>
                        <input type="hidden" name="id" value ="${user.getUserID()}"/>
                        <div class="form-group">
                            <label for="password" class="col-md-4 control-label">
                                New Password:
                            </label>
                            <div class="col-md-8">
                                <input type="password" 
                                       class="form-control" 
                                       id="password"
                                       name="password"/>
                            </div>
                        </div>
                        <div class="form-group">
                            <label for="confirmPassword" class="col-md-4 control-label">
                                Confirm New Password:
                            </label>
                            <div class="col-md-8">
                                <input type="password" 
                                       class="form-control" 
                                       id="confirmPassword"
                                       name="confirmPassword"/>
                            </div>
                        </div>
                        <div class="form-group">
                            <div class="col-md-offset-4 col-md-8">
                                <input type="submit" 
                                       class="btn btn-default" 
                                       id="search-button" 
                                       value="Update Password"/>
                            </div>
                        </div>
                    </form>
                </div>
            </div>
        </p>
    </div>
    <!-- Placed at the end of the document so the pages load faster -->
    <script src="${pageContext.request.contextPath}/js/jquery-3.1.1.min.js"></script>
    <script src="${pageContext.request.contextPath}/js/bootstrap.min.js"></script>

</body>
</html>