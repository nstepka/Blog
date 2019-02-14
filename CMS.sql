DROP DATABASE IF EXISTS CMS;
CREATE DATABASE CMS;
USE  CMS;

SET SQL_SAFE_UPDATES = 0;

CREATE TABLE `User` (
userid int primary key not null auto_increment,
userName varchar(50),
userPassword varchar(64)
);

INSERT INTO `User` (userName, userPassword) VALUES ('admin', '$2a$10$aa1tjClVVwo4PsW38UVVyO.J9qxw8ri/t8a7EjIogbvB929Se1qhG');


CREATE TABLE `Role`(
Roleid int primary key not null auto_increment,
roleName varchar (50)

);

INSERT INTO `Role` (roleName) VALUES ('ROLE_ADMIN'), ('ROLE_USER');

CREATE TABLE UserRole(
userRoleID int primary key not null auto_increment,
userID int,
RoleID int,
foreign key (userID) references `User`(userid),
foreign key (RoleID) references Role(Roleid)
);

INSERT INTO UserRole (userID, RoleID) VALUES ( 1, 1), (1, 2);

CREATE TABLE Tag(
TagID INT PRIMARY KEY NOT NULL auto_increment,
TagName varchar(50)
);

CREATE TABLE Post(
PostID INT PRIMARY KEY NOT NULL AUTO_INCREMENT,
PostDate date not null, 
PostTitle varchar (50),
PostStatus varchar (50),
postContent text,
Userid int,
foreign key (Userid) references `User`(userid)

);

CREATE TABLE PostTag(
postTagID int primary key not null auto_increment,
postID int,
tagId int,
foreign key (postID) references Post(PostID),
foreign key (tagId) references Tag(TagID)
);

