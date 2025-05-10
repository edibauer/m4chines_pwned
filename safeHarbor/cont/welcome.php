<?php
session_start();

if(is_null($_SESSION["loggedin"])){
	header("Location: /");
}

?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Harbor Bank Online</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.css">
    <style type="text/css">
        body{ font: 14px sans-serif; }
        .wrapper{ width: 350px; padding: 20px; }
    </style>
</head>
<body>
<h1>Harbor Bank Online</h1>
<nav class="navbar navbar-default">
  <div class="container-fluid">
    <div class="navbar-header">
      <a class="navbar-brand" href="#"></a>
    </div>
    <ul class="nav navbar-nav">
      <li class="active"><a href="#">Home</a></li>
      <li><a href="index.php?p=balance">Balance</a></li>
      <li><a href="index.php?p=transfer">Transfers</a></li>
      <li><a href="index.php?p=account">My Account</a></li>
      <li><a href="index.php?p=about">About</a></li>
      <li><a href="index.php?p=logout" onclick="confirm('Are you sure you want to log out?')">Log Out</a></li>
    </ul>
  </div>
</nav>
<div align="center">
<h4>Welcome, <?php echo $_SESSION["username"]; ?>.</h4>
<body>Use the menu above to perform your online banking.</body>
</div>