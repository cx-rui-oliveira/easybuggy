package org.t246osslab.easybuggy.vulnerabilities;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Locale;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.t246osslab.easybuggy.core.servlets.AbstractServlet;

@SuppressWarnings("serial")
@WebServlet(urlPatterns = { "/path-traversal" })
public class PathTraversalServlet extends AbstractServlet {

    private static final String BASE_DIR = System.getProperty("user.home") + "/easybuggy/files/";

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {

        try {
            String filename = req.getParameter("filename");
            Locale locale = req.getLocale();

            StringBuilder bodyHtml = new StringBuilder();

            bodyHtml.append("<form action=\"path-traversal\" method=\"get\">");
            bodyHtml.append(getMsg("description.read.file", locale));
            bodyHtml.append("<br><br>");
            bodyHtml.append(getMsg("label.filename", locale) + ": ");
            bodyHtml.append("<input type=\"text\" name=\"filename\" size=\"100\" maxlength=\"200\">");
            bodyHtml.append("<br><br>");
            bodyHtml.append("<input type=\"submit\" value=\"" + getMsg("label.submit", locale) + "\">");
            bodyHtml.append("<br><br>");

            if (!StringUtils.isBlank(filename)) {
                // Path traversal: filename is not validated, allows sequences like ../../etc/passwd
                File file = new File(BASE_DIR + filename);
                try {
                    String content = new String(Files.readAllBytes(file.toPath()));
                    bodyHtml.append("<pre>" + content + "</pre>");
                } catch (IOException e) {
                    bodyHtml.append(getErrMsg("msg.file.not.found", locale));
                }
            } else {
                bodyHtml.append(getMsg("msg.enter.filename", locale));
            }

            bodyHtml.append("<br><br>");
            bodyHtml.append(getInfoMsg("msg.note.path.traversal", locale));
            bodyHtml.append("</form>");

            responseToClient(req, res, getMsg("title.path.traversal.page", locale), bodyHtml.toString());

        } catch (Exception e) {
            log.error("Exception occurs: ", e);
        }
    }
}
