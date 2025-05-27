<%@ page contentType="text/html; charset=UTF-8" language="java" %>
<%@ taglib prefix="s" uri="/struts-tags" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Strutted™ - About Us</title>
    <meta charset="UTF-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">

    <style>
        html, body {
            height: 100%;
            margin: 0;
            font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
            background: #f5f5f5;
            color: #333;
        }
        .page-wrapper {
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }
        .header {
            background: linear-gradient(to right, #2c3e50, #4c5a6b);
            padding: 20px;
        }
        .header .navbar-brand {
            font-weight: 600;
            font-size: 1.5rem;
        }

        .hero-section {
            background: #2c3e50;
            color: #fff;
            padding: 60px 0;
            text-align: center;
        }
        .hero-section h1 {
            font-size: 2.5rem;
            font-weight: 300;
            margin-bottom: 20px;
        }
        .hero-section p {
            font-size: 1.2rem;
            margin: 0 auto;
            max-width: 700px;
        }

        .content-wrapper {
            flex: 1 0 auto;
        }

        .aboutus-container {
            max-width: 800px;
            margin: -30px auto 40px auto;
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 6px 20px rgba(0,0,0,0.1);
            padding: 30px;
        }
        .aboutus-container h2 {
            text-align: center;
            margin-bottom: 30px;
            font-weight: 600;
        }
        .aboutus-section {
            margin-bottom: 20px;
        }
        .aboutus-section h3 {
            font-weight: 600;
            margin-bottom: 10px;
        }
        .aboutus-section p {
            font-size: 1rem;
            color: #555;
        }
        .aboutus-section img {
            max-width: 100%;
            height: auto;
            border: 1px solid #ddd;
            border-radius: 8px;
            margin-top: 10px;
        }

        footer {
            background: #343a40;
            color: #fff;
            text-align: center;
            padding: 20px 0;
            flex-shrink: 0;
        }
        footer a {
            color: #adb5bd;
            text-decoration: none;
        }
        footer a:hover {
            color: #fff;
        }
    </style>
</head>

<body>
<div class="page-wrapper">
    <header class="header">
        <nav class="navbar navbar-expand-lg navbar-dark" style="background: transparent;">
            <a class="navbar-brand" href="upload">Strutted™</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarContent"
                    aria-controls="navbarContent" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
      
            <div class="collapse navbar-collapse" id="navbarContent">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item"><a class="nav-link" href="/">Home</a></li>
                    <li class="nav-item"><a class="nav-link" href="/how">How It Works</a></li>
                    <li class="nav-item"><a class="nav-link active" href="#">About Us</a></li>
                </ul>
            </div>
        </nav>
    </header>

    <div class="content-wrapper">
        <div class="hero-section">
            <div class="container">
                <h1>About Us</h1>
                <p>Discover the story behind Strutted™, a leading image hosting service dedicated to simplifying how you share your memories.</p>
            </div>
        </div>

        <div class="aboutus-container text-center">
            <h2>Our Story</h2>
            <div class="aboutus-section">
                <h3>Who We Are</h3>
                <p>
                    Founded in 2023 and based in the heart of the UK, Strutted™ is a pioneering company specializing in secure and efficient image hosting solutions. Our mission is to provide users with a reliable platform to upload, store, and share their images effortlessly.
                </p>
            </div>

            <div class="aboutus-section">
                <h3>What We Do</h3>
                <p>
                    At Strutted™, we understand the importance of preserving and sharing your precious moments. Our state-of-the-art hosting services ensure that your images are stored safely and can be accessed or shared with a simple, short link. Whether you're a professional photographer or someone who loves capturing daily moments, Strutted™ offers the perfect solution for all your image hosting needs.
                </p>
            </div>

            <div class="aboutus-section">
                <h3>Our Vision</h3>
                <p>
                    Strutted™ is committed to revolutionizing the image hosting industry by introducing innovative features that enhance user experience. We aim to expand our services globally, making image sharing quicker, more secure, and accessible to everyone.
                </p>
            </div>

            <div class="aboutus-section">
                <h3>Why Choose Us</h3>
                <p>
                    * <b>Security</b>: We prioritize the safety of your images with advanced encryption and secure storage solutions.
                    <br><br>
                    * <b>Simplicity</b>: Our user-friendly interface makes uploading and sharing images a breeze. Feel free to use our Docker image as a base template for your projects!
                    <br><br>
                    * <b>Reliability</b>: With 99.9% uptime and robust infrastructure, your images are always accessible when you need them.
                    <br><br>
                    * <b>Support</b>: Our dedicated support team is here to assist you with any queries or issues.
                </p>
            </div>
        </div>
    </div>

    <footer>
        <div class="container" style="margin-top: 9px;">
            <p>© 2024 Strutted™ – All rights reserved.</p>
        </div>
    </footer>
</div>

<!-- Bootstrap JS Bundle with Popper -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>

</body>
</html>