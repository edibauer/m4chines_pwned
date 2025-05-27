<%@ page contentType="text/html; charset=UTF-8" language="java" %>
<%@ taglib prefix="s" uri="/struts-tags" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Strutted™ - How It Works</title>
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

        .howitworks-container {
            max-width: 800px;
            margin: -30px auto 40px auto;
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 6px 20px rgba(0,0,0,0.1);
            padding: 30px;
        }
        .howitworks-container h2 {
            text-align: center;
            margin-bottom: 30px;
            font-weight: 600;
        }
        .step {
            margin-bottom: 20px;
        }
        .step img {
            max-width: 100%;
            height: auto;
            border: 1px solid #ddd;
            border-radius: 8px;
            margin-bottom: 10px;
        }
        .step-title {
            font-weight: 600;
            font-size: 1.25rem;
            margin-bottom: 5px;
        }
        .step-description {
            font-size: 1rem;
            color: #555;
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
            <a class="navbar-brand" href="#">Strutted™</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarContent"
                    aria-controls="navbarContent" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
      
            <div class="collapse navbar-collapse" id="navbarContent">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item"><a class="nav-link" href="/">Home</a></li>
                    <li class="nav-item"><a class="nav-link active" href="#">How It Works</a></li>
                    <li class="nav-item"><a class="nav-link" href="/about">About Us</a></li>
                </ul>
            </div>
        </nav>
    </header>

    <div class="content-wrapper">
        <div class="hero-section">
            <div class="container">
                <h1>How It Works</h1>
                <p>Learn how to effortlessly upload your images and share them with friends using Strutted™.</p>
            </div>
        </div>

        <div class="howitworks-container text-center">
            <h2>Step-by-Step Guide</h2>
            
            <div class="step">
                <div class="step-title">1. Choose Your Image</div>
                <div class="step-description">
                    Upload an image file in any acceptable format (JPG, JPEG, PNG, GIF).
                </div>
                <img src="https://via.placeholder.com/800x400.png?text=Choose+Your+Image" alt="Choose Your Image">
            </div>
            
            <div class="step">
                <div class="step-title">2. Upload Easily</div>
                <div class="step-description">
                    Click the upload button and let Strutted™ handle the rest. Your image is securely stored.
                </div>
                <img src="https://via.placeholder.com/800x400.png?text=Upload+Easily" alt="Upload Easily">
            </div>
            
            <div class="step">
                <div class="step-title">3. Get Your Shareable Link</div>
                <div class="step-description">
                    Receive a unique, short link that you can share instantly with your friends and family.
                </div>
                <img src="https://via.placeholder.com/800x400.png?text=Get+Your+Shareable+Link" alt="Get Your Shareable Link">
            </div>
            
            <div class="step">
                <div class="step-title">4. Share and Enjoy!</div>
                <div class="step-description">
                    Share the link anywhere—social media, messaging apps, or via email. Access your images anytime, anywhere.
                </div>
                <img src="https://via.placeholder.com/800x400.png?text=Share+and+Enjoy" alt="Share and Enjoy">
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