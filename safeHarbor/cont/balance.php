<?php
session_start();

if(is_null($_SESSION["loggedin"])){
	header("Location: /");
}


$dbServer = mysqli_connect('mysql', 'root', 'TestPass123!', 'HarborBankUsers');
$user = $_SESSION["username"];
$balanceQueryResult = mysqli_query($dbServer, "SELECT balance FROM users WHERE username = '$user'");
$balanceRow = mysqli_fetch_row($balanceQueryResult);
$balance = $balanceRow[0];
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
      <li><a href="index.php?p=welcome">Home</a></li>
      <li class="active"><a href="index.php?p=balance">Balance</a></li>
      <li><a href="index.php?p=transfer">Transfers</a></li>
      <li><a href="index.php?p=account">My Account</a></li>
      <li><a href="index.php?p=about">About</a></li>
      <li><a href="index.php?p=logout" onclick="confirm('Are you sure you want to log out?')">Log Out</a></li>
    </ul>
  </div>
</nav>
<div align="center">
<h4>Your current account balance is $<?php echo $balance; ?></h4>
<body>If you would like to make a deposit, please call (555) 867-5309</body>
</div>