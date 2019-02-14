<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="s" uri="http://www.springframework.org/tags"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
    <head>
        <title>Index Page</title>
        <!-- Bootstrap core CSS -->
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css" integrity="sha384-MCw98/SFnGE8fJT3GXwEOngsV7Zt27NXFoaoApmYm81iuXoPkFOJwJ8ERdknLPMO" crossorigin="anonymous"> 
        <link href="https://fonts.googleapis.com/css?family=Playfair+Display:700,900" rel="stylesheet">
        <link href="css/blog.css" rel="stylesheet">
    </head>
    <body>

        <div class="container">
            <header class="blog-header py-3">
                <div class="row flex-nowrap justify-content-between align-items-center">

                    <div class="col-12 text-center">
                        </br>
                        <a class="blog-header-logo text-dark" href="${pageContext.request.contextPath}/">YOUR WONDERFUL COMPANY BLOG</a>
                        </br>
                    </div>
                    </br>

                </div>
            </header>

        </div>

    <center>

        </br>
        <b><p> Here are my super duper blog thoughts!</p></b>
        </br>
        <div class="container">
            <div class="card">
                <c:forEach var="post" items="${postList}">


                    <div class="card-header">
                        <p style="text-align:left;">
                            Post Title

                            <a href="displayPostDetail?postid=${post.postid}">
                                <c:out value="${post.getPostTitle()}"/> 
                            </a>
                    
                    <span style="float:right;"> 
                        Date of Post:  <c:out value="${post.postDate}"/></span>
                        </p>
                </div>
                <div class="card-body">
                    <blockquote class="blockquote mb-0">
                        ${post.getPostContent()}
                        <c:forEach var="tag" items="${post.tag}">
                            <a href="displayTagDetails?tagID=${tag.tagid}">
                                <c:out value="${tag.tagName}"/> 
                            </a>
                            </br>
                        </c:forEach> 
                        <footer class="blockquote-footer">Posted By :<c:out value="${post.user.userName}"/> </footer>
                    </blockquote>
                </div>
            </c:forEach>         
        </div>                
    </div>
        
        </br>
        </br>
        </br>
        </br>
        </br>
        </br>
        <footer>
             <div class="nav-scroller py-1 mb-2">
            <nav class="centered col-10 nav d-flex justify-content-between text-center">
                <a class="p-2 text-muted" href="${pageContext.request.contextPath}/displayCreatePost">Create Post</a>
                <a class="p-2 text-muted" href="${pageContext.request.contextPath}/login">Login Page</a>
                <sec:authorize access="isAuthenticated()">
                    <form class="form-inline" 
                          method="POST" 
                          action="${pageContext.request.contextPath}/logout">
                        <input type="hidden" 
                               name="${_csrf.parameterName}" 
                               value="${_csrf.token}"/>
                        <label for="submit">
                            ${pageContext.request.userPrincipal.name}&nbsp;&nbsp;&nbsp;
                        </label>
                        <button class="btn btn-link" 
                                id="submit" 
                                type="submit">Logout</button>
                    </form>
                </sec:authorize>
            </nav>
        </div>
    </center>
</main><!-- /.container -->

<script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>
</html>

