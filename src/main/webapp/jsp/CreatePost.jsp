<%-- 
    Document   : CreateBlog
    Created on : Oct 22, 2018, 1:11:45 PM
    Author     : nstep
--%>

<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="s" uri="http://www.springframework.org/tags"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<%@ page contentType="text/html" pageEncoding="UTF-8"%>
<html>
    <head>




        <link href="${pageContext.request.contextPath}/css/bootstrap.min.css" rel="stylesheet"> 
        <script src="https://cloud.tinymce.com/stable/tinymce.min.js?apiKey=6rgy9j5tfzfqeo9ymsgcqw3xebokijmgrzs7x1aac9djesci"></script>
        <script type="text/javascript">
            tinymce.init({
                selector: '#mytextarea'
            });
        </script>
    </head>
    <body>
        <div class="container">
            <h1>Approve Post</h1>
            <hr/>
            <div class="navbar">
                <ul class="nav nav-tabs">
                    <li role="presentation">
                        <a href="${pageContext.request.contextPath}/">
                            Home Page
                        </a>
                    </li>
                    <li role="presentation">
                        <a href="${pageContext.request.contextPath}/displayCreateTagPage">
                            Create Tag
                        </a>
                    </li>
                    <li role="presentation" class="active">
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
            <form class="form-horizontal"
                  method="POST" role="form"
                  action="createPost">
                <textarea id="mytextarea" name="userPost">Hello World!!!</textarea>
                <br>

                <div class="form-group">
                    <label for="tagPost" class="col-md-4 control-label">
                        Tags:
                    </label>
                    <div class="col-md-8">
                        <select multiple name="tagPost" 
                                id="tags" style="width: 100%" 
                                required>
                            <c:forEach var="tag" items="${tags}">
                                <option value="${tag.tagid}">
                                    ${tag.tagName}
                                </option>
                            </c:forEach>
                        </select>
                    </div>
                    <br>
                    <input type="hidden" name="${_csrf.parameterName}" 
                           value="${_csrf.token}"/>
                    <sf:hidden path="postID"/>
                    <div class="col-md-8">
                        <label for="title">Title:</label>
                        <input type="title" name="title" id="title" required />
                    </div>
                    <div class="col-md-8">
                        <input type="submit" class="btn btn-default" value="Submit Post"/>
                    </div>
                </div>

            </form>
    </body>
</html>