# Strutted™ - User Guide

Strutted™ is a secure and efficient image hosting service designed for quick and easy sharing of your images. This guide will walk you through the steps to use the application effectively, including uploading images, obtaining shareable links, and viewing shared images.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Setup Instructions](#setup-instructions)
3. [Uploading an Image](#uploading-an-image)
4. [Obtaining a Shareable Link](#obtaining-a-shareable-link)
5. [Viewing a Shared Image](#viewing-a-shared-image)
6. [Frequently Asked Questions (FAQs)](#frequently-asked-questions-faqs)
7. [Support](#support)

---

## Introduction

Strutted™ allows you to upload images in various formats (JPG, JPEG, PNG, GIF) and provides a unique, short link that you can share with friends, family, or colleagues. The service is designed to be simple, fast, and secure, ensuring your images are hosted reliably.

---

## Setup Instructions

Before using Strutted™, you'll need to set up the application on your local machine or server using Docker. Follow these steps:

```sh
cd strutted-app
docker build . -t strutted:latest
docker run -p 8080:8080 strutted:latest
```
---

## Uploading an Image

Follow these steps to upload an image:

1. **Navigate to the Upload Page:**
   - Open your web browser and go to `http://localhost:8080` (or your Strutted™ application URL).
   - You will see the Upload page with an option to choose a file.

2. **Select Your Image:**
   - Click on the file input field labeled "Choose an image to upload:".
   - Browse your computer and select the image file you want to upload. Supported file types include JPG, JPEG, PNG, and GIF.

3. **Upload the Image:**
   - After selecting the image, click the **Upload** button.
   - The application will process the upload. If successful, you will be redirected to a confirmation page.

---

## Obtaining a Shareable Link

Once your image is successfully uploaded:

1. **View the Confirmation Page:**
   - After the upload process completes, you will see a success message along with a shareable link.

2. **Copy the Shareable Link:**
   - The shareable link is displayed in a read-only input field.
   - Click the **Copy Link** button next to the input field to copy the link to your clipboard.

3. **Share the Link:**
   - Paste the copied link into an email, chat, social media post, or anywhere else you'd like to share your image.
   - Your recipients can click on the link to view the uploaded image.

---

## Viewing a Shared Image

To view an image using a shareable link:

1. **Access the Link:**
   - Click the shareable link that you or someone else received. It should look something like `http://localhost:8080/s/{id}` where `{id}` is a unique identifier.

2. **Image Display:**
   - The link will take you to a page that displays the uploaded image.
   - You can view the image directly in your browser and even download it if needed.

3. **Additional Actions:**
   - On the image viewing page, you may have options to upload another image or navigate back to the main page.

---

## Frequently Asked Questions (FAQs)

**Q: What image formats are supported?**  
A: Strutted™ supports JPG, JPEG, PNG, and GIF formats.

**Q: How long will my image be hosted?**  
A: Your images are hosted securely on Strutted™ servers. For specifics on retention policies, please refer to our terms and conditions.

**Q: Is my uploaded image secure?**  
A: Yes, Strutted™ uses secure storage solutions and transmission protocols to ensure the safety and privacy of your images.

**Q: Can I delete my uploaded images?**  
A: No, image uploads are permanent once uploaded to our CDN.

---

## Support

If you encounter any issues or have questions not covered in this guide, please reach out to our support team:

- **Email:** support@strutted.com

We are here to help you make the most out of the Strutted™ image hosting service.

---

Thank you for choosing Strutted™! We hope you enjoy a seamless and efficient image sharing experience.
