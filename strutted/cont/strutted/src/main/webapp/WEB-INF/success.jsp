<%@ page contentType="text/html; charset=UTF-8" language="java" %>
<%@ taglib prefix="s" uri="/struts-tags" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Strutted™ - Upload Successful!</title>
    <meta charset="UTF-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
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

        .success-container {
            max-width: 700px;
            margin: -30px auto 40px auto;
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 6px 20px rgba(0,0,0,0.1);
            padding: 30px;
        }
        .success-container h2 {
            text-align: center;
            margin-bottom: 30px;
            font-weight: 600;
        }
        .messages {
            margin-bottom: 30px;
            text-align: center;
            font-size: 1.1rem;
        }
        .messages img {
            max-width: 100%;
            margin-top: 20px;
            border: 1px solid #ddd;
            border-radius: 8px;
        }
        .back-link {
            display: block;
            text-align: center;
            margin-top: 30px;
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
            <a class="navbar-brand" href="/">Strutted™</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarContent"
                    aria-controls="navbarContent" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
      
            <div class="collapse navbar-collapse" id="navbarContent">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item"><a class="nav-link active" href="/">Home</a></li>
                    <li class="nav-item"><a class="nav-link" href="/how">How It Works</a></li>
                    <li class="nav-item"><a class="nav-link" href="/about">About Us</a></li>
                </ul>
            </div>
        </nav>
    </header>

    <div class="content-wrapper">
        <div class="hero-section">
            <div class="container">
                <h1>Image Upload Successful!</h1>
                <p>Congratulations! Your image has been securely uploaded and is now accessible via a shareable link.</p>
            </div>
        </div>

        <div class="success-container">
            <div class="messages">
                <s:if test="hasActionMessages()">
                    <div class="mb-3 mt-1 back-link">
                        <input type="text" class="form-control" style="display:none;" id="shareableLink" value="<s:property value='shortenedUrl'/>" readonly>
                        <button class="btn btn-outline-secondary" type="button" id="copyButton">Copy Shareable Link</button>
                    </div>
                    <img src="<s:property value='imagePath'/>" alt="Uploaded File"/>
                </s:if>
                <s:if test="hasActionErrors()">
                    <div class="alert alert-danger" role="alert">
                        <s:iterator value="actionErrors">
                            <s:property/>
                        </s:iterator>
                    </div>
                </s:if>
            </div>

            <div class="back-link">
                <s:url var="uploadActionUrl" action="upload"/>
                <a href="<s:property value='#uploadActionUrl'/>" class="btn btn-outline-secondary">Upload Another File</a>
            </div>
        </div>
    </div>

    <footer>
        <div class="container" style="margin-top: 9px;">
            <p>© 2024 Strutted™ – All rights reserved.</p>
        </div>
    </footer>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
    document.addEventListener("DOMContentLoaded", function() {
        const copyButton = document.getElementById('copyButton');
        const shareableLink = document.getElementById('shareableLink');

        copyButton.addEventListener('click', function() {
            // Select the text field
            shareableLink.select();
            shareableLink.setSelectionRange(0, 99999);

            // Copy the text inside the text field
            navigator.clipboard.writeText(shareableLink.value)
                .then(() => {
                    // Success feedback
                    copyButton.textContent = 'Copied!';
                    copyButton.classList.remove('btn-outline-secondary');
                    copyButton.classList.add('btn-success');
                    setTimeout(() => {
                        copyButton.textContent = 'Copy Shareable Link';
                        copyButton.classList.remove('btn-success');
                        copyButton.classList.add('btn-outline-secondary');
                    }, 2000);
                })
                .catch(err => {
                    // Error feedback
                    console.error('Failed to copy: ', err);
                    copyButton.textContent = 'Error!';
                    copyButton.classList.remove('btn-outline-secondary');
                    copyButton.classList.add('btn-danger');
                    setTimeout(() => {
                        copyButton.textContent = 'Copy Shareable Link';
                        copyButton.classList.remove('btn-danger');
                        copyButton.classList.add('btn-outline-secondary');
                    }, 2000);
                });
        });
    });
</script>
</body>
</html>