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
            <h1>Blog Admin Page: Add a Tag</h1>
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
                    <h2>Tags</h2>
                    <table id="contactTable" class="table table-hover">
                        <tr>
                            <th width="70%">Tag name</th>
                            <th width="30%"></th>
                        </tr>
                        <c:forEach var="tag" items="${tagList}">
                            <tr>
                                <td>
                                    <a href="displayTagDetails?tagid=${tag.tagid}">
                                        <c:out value="${tag.tagName}"/>
                                    </a>
                                </td>
                                <td>
                                    <a href="deleteTag?tagid=${tag.tagid}">
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
                <div class="col-md-6">
                    <h2>Add New Tag</h2>
                    <form class="form-horizontal" 
                          role="form" method="POST" 
                          action="CreateTag">
                        <div class="form-group">
                            <label for="add-tag-name" class="col-md-4 control-label">#Tag Name:</label>
                            <div class="col-md-8">
                                <input type="text" class="form-control" name="tagName" placeholder="#tag" required/>
                            </div>
                        </div>
                        <input type="hidden" 
                               name="${_csrf.parameterName}" 
                               value="${_csrf.token}"/>
                        <input type="hidden" 
                               name="id" 
                               value="${currentUser.getUserID()}"/>
                        <div class="form-group">
                            <div class="col-md-offset-4 col-md-8">
                                <input type="submit" class="btn btn-default" value="Create Tag"/>
                            </div>
                        </div>
                    </form>

                </div> <!-- End col div -->

            </div> <!-- End row div -->
            <!-- Main Page Content Stop -->    
        </div>
        <!-- Placed at the end of the document so the pages load faster -->
        <script src="${pageContext.request.contextPath}/js/jquery-3.1.1.min.js"></script>
        <script src="${pageContext.request.contextPath}/js/bootstrap.min.js"></script>

    </body>
</html>