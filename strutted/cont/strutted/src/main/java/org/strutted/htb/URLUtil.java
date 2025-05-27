package org.strutted.htb;

import com.opensymphony.xwork2.ActionSupport;
import org.apache.struts2.ServletActionContext;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.strutted.htb.URLMapping;
import org.apache.commons.lang3.StringUtils;

public class URLUtil extends ActionSupport {
    private String id;
    private String storedImagePath;
    private URLMapping urlMapping = new URLMapping();

    public String execute() throws Exception {
        if (id == null || id.isEmpty()) {
            addActionError("Invalid URL.");
            return ERROR;
        }

        this.storedImagePath = urlMapping.getImagePath(id);
        if (storedImagePath == null) {
            addActionError("The requested resource does not exist.");
            return ERROR;
        }

        return SUCCESS; 
    }

    public String getImagePath() {
        return storedImagePath;
    }
    public void setImagePath(String storedImagePath) {
        this.storedImagePath = storedImagePath;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }
}