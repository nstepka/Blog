<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="s" uri="http://www.springframework.org/tags"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
    <head>
        <title>BLOG ADD A TAG</title>
        <!-- Bootstrap core CSS -->
        <link href="${pageContext.request.contextPath}/css/bootstrap.min.css" rel="stylesheet">        
    </head>
    <body>
        <div class="container">
            <h1>Blog Admin Page: View Post</h1>
            <hr/>
            <div class="navbar">
                <ul class="nav nav-tabs">
                    <li role="presentation">
                        <a href="${pageContext.request.contextPath}/">
                            Home Page
                        </a>
                    </li>
                    <li role="presentation" >
                        <a href="${pageContext.request.contextPath}/displayCreateTagPage">
                            Create Tag
                        </a>
                    </li>
                    <li role="presentation">
                        <a href="${pageContext.request.contextPath}/displayCreatePost">
                            Create Post
                        </a>
                    </li>
                   
                    <li role="presentation" class="active">
                        <a href="${pageContext.request.contextPath}/displayPostView">
                            List Post
                        </a>
                    </li>
                    
                </ul>    
            </div>
            <!-- Main Page Content Start -->
            <!-- 
    Add a row to our container - this will hold the summary table and the new
    contact form.
            -->
            <div class="row">
                <!-- 
                    Add a col to hold the summary table - have it take up half the row 
                -->
                <div class="col-md-6">
                    <h2>Post</h2>
                    <table id="contactTable" class="table table-hover">
                        <tr>
                            <th width="30%">Post name</th>
                            <th width="30%">Date Posted</th>
                            <th width="20%">Submitted By</th>
                            <th width="20%">Delete Post</th>
                        </tr>
                        <c:forEach var="post" items="${postList}">
                            <tr>
                                
                                <td>
                                    <a href="displayPostDetail?postid=${post.postid}">
                                        <c:out value="${post.postTitle}"/>
                                    </a>
                                </td>
                                <td>
                                        <c:out value="${post.postDate}"/>
                                    
                                </td>
                                <td>
                                    <c:out value="${post.user.userName}"/>
                                </td>
                                <td>
                                    <a href="deletePost?postid=${post.postid}">
                                        Delete
                                    </a>
                                </td>
                            </tr>
                        </c:forEach>
                    </table>                  
                </div> <!-- End col div -->
                <!-- 
                    Add col to hold the new contact form - have it take up the other 
                    half of the row
                -->
                

            </div> <!-- End row div -->
            <!-- Main Page Content Stop -->    
        </div>
        <!-- Placed at the end of the document so the pages load faster -->
        <script src="${pageContext.request.contextPath}/js/jquery-3.1.1.min.js"></script>
        <script src="${pageContext.request.contextPath}/js/bootstrap.min.js"></script>

    </body>
</html>