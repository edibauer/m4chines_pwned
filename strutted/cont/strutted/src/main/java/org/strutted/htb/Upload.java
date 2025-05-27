package org.strutted.htb;

import com.opensymphony.xwork2.ActionSupport;
import java.io.File;
import java.text.SimpleDateFormat;
import java.io.InputStream;
import java.io.FileInputStream;
import java.util.Date;
import java.util.HashMap;
import java.util.UUID;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.struts2.ServletActionContext;
import org.strutted.htb.URLUtil;
import org.strutted.htb.URLMapping;

public class Upload extends ActionSupport {
    private File upload;
    private String uploadFileName;
    private String uploadContentType;
    private String imagePath;
    public String shortenedUrl;
    private String fullUrl;
    private String relativeImagePath;

    private URLMapping urlMapping = new URLMapping();

    @Override
    public String execute() throws Exception {
        String method = ServletActionContext.getRequest().getMethod();
        boolean noFileSelected = (upload == null || StringUtils.isBlank(uploadFileName));

        if (noFileSelected) {
            if ("POST".equalsIgnoreCase(method)) {
                addActionError("Please select a file to upload.");
            }
            return INPUT;
        }

        String extension = "";
        int dotIndex = uploadFileName.lastIndexOf('.');
        if (dotIndex != -1 && dotIndex < uploadFileName.length() - 1) {
            extension = uploadFileName.substring(dotIndex).toLowerCase();
        }

        if (!isAllowedContentType(uploadContentType)) {
            addActionError("Only image files can be uploaded!");
            return INPUT;
        }

        if (!isImageByMagicBytes(upload)) {
            addActionError("The file does not appear to be a valid image.");
            return INPUT;
        }

        String baseUploadDirectory = System.getProperty("user.dir") + "/webapps/ROOT/uploads/";
        File baseDir = new File(baseUploadDirectory);
        if (!baseDir.exists() && !baseDir.mkdirs()) {
            addActionError("Server error: could not create base upload directory.");
            return INPUT;
        }

        String timeStamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        File timeDir = new File(baseDir, timeStamp);
        if (!timeDir.exists() && !timeDir.mkdirs()) {
            addActionError("Server error: could not create timestamped upload directory.");
            return INPUT;
        }

        String relativeImagePath = "uploads/" + timeStamp + "/" + uploadFileName;
        this.imagePath = relativeImagePath;
        String fullUrl = constructFullUrl(relativeImagePath);

        try {
            File destFile = new File(timeDir, uploadFileName);
            FileUtils.copyFile(upload, destFile);
            String shortId = generateShortId();
            boolean saved = urlMapping.saveMapping(shortId, fullUrl);
            if (!saved) {
                addActionError("Server error: could not save URL mapping.");
                return INPUT;
            }

            this.shortenedUrl = ServletActionContext.getRequest().getRequestURL()
                .toString()
                .replace(ServletActionContext.getRequest().getRequestURI(), "") + "/s/" + shortId;

            addActionMessage("File uploaded successfully <a href=\"" + shortenedUrl + "\" target=\"_blank\">View your file</a>");
            return SUCCESS;

        } catch (Exception e) {
            addActionError("Error uploading file: " + e.getMessage());
            e.printStackTrace();
            return INPUT;
        }
    }

    private boolean isAllowedContentType(String contentType) {
        String[] allowedTypes = {"image/jpeg", "image/png", "image/gif"};
        for (String allowedType : allowedTypes) {
            if (allowedType.equalsIgnoreCase(contentType)) {
                return true;
            }
        }
        return false;
    }

    private boolean isImageByMagicBytes(File file) {
        byte[] header = new byte[8];
        try (InputStream in = new FileInputStream(file)) {
            int bytesRead = in.read(header, 0, 8);
            if (bytesRead < 8) {
                return false;
            }

            // JPEG
            if (header[0] == (byte)0xFF && header[1] == (byte)0xD8 && header[2] == (byte)0xFF) {
                return true;
            }

            // PNG
            if (header[0] == (byte)0x89 && header[1] == (byte)0x50 && header[2] == (byte)0x4E && header[3] == (byte)0x47) {
                return true;
            }

            // GIF (GIF87a or GIF89a)
            if (header[0] == (byte)0x47 && header[1] == (byte)0x49 && header[2] == (byte)0x46 &&
                header[3] == (byte)0x38 && (header[4] == (byte)0x37 || header[4] == (byte)0x39) && header[5] == (byte)0x61) {
                return true;
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    private String generateShortId() {
        return UUID.randomUUID().toString().substring(0, 8);
    }

    private String constructFullUrl(String relativePath) {
        String scheme = ServletActionContext.getRequest().getScheme();
        String serverName = ServletActionContext.getRequest().getServerName();
        int serverPort = ServletActionContext.getRequest().getServerPort();
        String contextPath = ServletActionContext.getRequest().getContextPath();

        StringBuilder url = new StringBuilder();
        url.append(scheme).append("://").append(serverName);

        if ((scheme.equals("http") && serverPort != 80) ||
            (scheme.equals("https") && serverPort != 443)) {
            url.append(":").append(serverPort);
        }

        url.append(contextPath).append("/").append(relativePath);

        return url.toString();
    }

    public File getUpload() {
        return upload;
    }
    public void setUpload(File upload) {
        this.upload = upload;
    }

    public String getUploadFileName() {
        return uploadFileName;
    }
    public void setUploadFileName(String uploadFileName) {
        this.uploadFileName = uploadFileName;
    }

    public String getUploadContentType() {
        return uploadContentType;
    }
    public void setUploadContentType(String uploadContentType) {
        this.uploadContentType = uploadContentType;
    }

    public String getShortenedUrl() {
        return shortenedUrl;
    }

    public void setShortenedUrl(String shortenedUrl) {
        this.shortenedUrl = shortenedUrl;
    }

    public String getImagePath() {
        return imagePath;
    }
    public void setImagePath(String imagePath) {
        this.imagePath = imagePath;
    }
}