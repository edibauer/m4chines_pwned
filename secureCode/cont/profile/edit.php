<?php
include "../include/header.php";    
include "../include/isAuthenticated.php";
$data = mysqli_query($conn, "SELECT * FROM user where id='$sid'");
$result = mysqli_fetch_array($data);
?>
</head>
<body>
    <div class="container">
    <div class="panel panel-primary">
            <div class="panel-heading">
                <center>Profile</center>
            </div>
            <div class="panel-body">
            <form action="update.php" method="post" class="form-horizontal col-md-6">
                <div class="form-group">
                    <label class="control-label col-sm-2" for="username">Username</label>
                        <div class="col-sm-10">
                            <input type="text" name="username" class="form-control col-md-8" id="username" placeholder="Username"value="<?php echo htmlentities($result['username']); ?>">
                        </div>
                </div>
                <div class="form-group">
                    <label class="control-label col-sm-2" for="username">Gender</label>
                        <div class="col-sm-10">
                                <select name="gender" class="form-control col-md-8" id="gender">
                                    <option value="Male">Male</option>
                                    <option value="Female">Female</option>
                                </select>
                            </div>
                        </div>
                        <input type="submit" value="Submit" class="btn btn-primary">
                </form>
            </div>
                
            </div>
        </div>
    </div>
</body>
</html>