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
                    <p>
                        Name: <c:out value="${tag.tagName}"/> 
                    </p>
                    <p> List of Post that have this tag: </p>
                    <p>
                        <c:forEach var="currentPost" items="${post}">
                            <a href="displayPostDetail?postid=${currentPost.postid}">
                            <c:out value="${currentPost.postTitle}"/>
                            </a>
                            </br>   
                        </c:forEach>     
                    </p>

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