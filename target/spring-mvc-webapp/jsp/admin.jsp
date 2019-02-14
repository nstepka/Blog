<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="s" uri="http://www.springframework.org/tags"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
    <head>
        <title>CMS Admin</title>
        <!-- Bootstrap core CSS -->
        <link href="${pageContext.request.contextPath}/css/bootstrap.min.css" rel="stylesheet">        
    </head>
    <body>
        <div class="container">
            <h1>CMS Administrator Page</h1>
            <hr/>
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
                    <button class="btn btn-link" 
                            id="submit" 
                            type="submit">Logout</button>
                </form>
            </sec:authorize>
        </div>
                        
        <div class="container">
            <div class="row">
                <h3>Add User</h3>
                <form class="form form-inline" 
                      method="POST" 
                      action="${pageContext.request.contextPath}/addUser">
                    <input type="hidden" 
                           name="${_csrf.parameterName}" 
                           value="${_csrf.token}"/>
                    <label for="username">Username:</label>
                    <input type="text" name="username" id="username">
                    <label for="password">Password:</label>
                    <input type="password" name="password" id="password">
                    <button type="submit">Add User</button>
                </form>
            </div>
        </div>
        <div class="container">
            <div class ="row">
                <h3>Users</h3>
                <table class="table table-bordered">
                    <tr>
                        <th>Username</th>
                        <th>Roles</th>
                        <th>Edit</th>
                        <th>Delete</th>
                    </tr>
                    <c:forEach items="${users}" var="currentUser">
                        <tr>
                            <td><c:out value="${currentUser.getUserName()}"/></td>
                            <td>
                                <c:forEach items="${currentUser.getRoles()}" var="currentRole">
                                    <c:out value="${currentRole.getRoleType()}"/>&nbsp;
                                </c:forEach>
                            </td>
                            <td><a href="${pageContext.request.contextPath}/editUser?id=${currentUser.getUserID()}">Edit</a></td>
                            <td>
                                <form class="form-inline" 
                                      method="POST" 
                                      action="${pageContext.request.contextPath}/deleteUser">
                                    <input type="hidden" 
                                           name="${_csrf.parameterName}" 
                                           value="${_csrf.token}"/>
                                    <input type="hidden" 
                                           name="id" 
                                           value="${currentUser.getUserID()}"/>
                                    <button class="btn btn-link btn-xs" type="submit">Delete</button>
                                </form>
                            </td>
                        </tr>
                    </c:forEach>
                </table>
            </div>
        </div>
        <!-- Placed at the end of the document so the pages load faster -->
        <script src="${pageContext.request.contextPath}/js/jquery-3.1.1.min.js"></script>
        <script src="${pageContext.request.contextPath}/js/bootstrap.min.js"></script>

    </body>
</html>