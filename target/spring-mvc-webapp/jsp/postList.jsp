<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="s" uri="http://www.springframework.org/tags"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

    <head>
        <title>Title</title>
        <style>
            div{
                font-family: sans-serif;
            }
            #navigation,
            .heading {
                text-align: center;
                width: 100%;
                margin: auto;
                background-color: #fafafa;
            }
            .content{
                text-align: center;
            }
            .container {
                text-align: left;
                background-color: #ffffff;
                max-width: 700px;
                width: 100%;
                margin: auto;
                display: inline-block;
            }

            .centered-form {
            }
        </style>
        <link href="${pageContext.request.contextPath}/css/bootstrap.min.css" rel="stylesheet">

    </head>

    <body>
        <div class="heading">
            <h1>Blog Platform</h1>
            <div id="navigation">
                <div class="row nav-row">
                    <a href="">Home</a> |
                    <a href="">Static #1</a> |
                    <a href="">Static #2</a> |
                    <a href="">Static #3</a> |
                    <a href="">Login</a>
                </div>
            </div>
            <hr/>
        </div>
        <div class="content">
            <!--This is where the headings of each post will appear for the post browsing mode-->
        </div>
        <div class="footer">
            <footer>
                <p>
                    Copyright --your company here-- October 2018
                </p>
            </footer>
        </div>

        <script src="${pageContext.request.contextPath}/js/jquery-3.1.1.min.js"></script>
        <script src="${pageContext.request.contextPath}/js/bootstrap.min.js"></script>
    </body>
</html>