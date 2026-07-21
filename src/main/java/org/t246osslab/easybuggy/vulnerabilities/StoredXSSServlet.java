package org.t246osslab.easybuggy.vulnerabilities;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.t246osslab.easybuggy.core.servlets.AbstractServlet;

@SuppressWarnings("serial")
@WebServlet(urlPatterns = { "/stored-xss" })
public class StoredXSSServlet extends AbstractServlet {

    private static final List<String> comments = Collections.synchronizedList(new ArrayList<String>());

    @Override
    public void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        String comment = req.getParameter("comment");
        if (!StringUtils.isBlank(comment)) {
            // Stored XSS: comment is persisted without sanitization
            comments.add(comment);
        }
        res.sendRedirect("stored-xss");
    }

    @Override
    public void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        try {
            Locale locale = req.getLocale();
            StringBuilder bodyHtml = new StringBuilder();

            bodyHtml.append("<form action=\"stored-xss\" method=\"post\">");
            bodyHtml.append(getMsg("description.post.comment", locale));
            bodyHtml.append("<br><br>");
            bodyHtml.append(getMsg("label.comment", locale) + ": ");
            bodyHtml.append("<input type=\"text\" name=\"comment\" size=\"100\" maxlength=\"500\">");
            bodyHtml.append("<br><br>");
            bodyHtml.append("<input type=\"submit\" value=\"" + getMsg("label.submit", locale) + "\">");
            bodyHtml.append("</form>");
            bodyHtml.append("<br>");

            bodyHtml.append("<h4>" + getMsg("label.comments", locale) + "</h4>");
            if (comments.isEmpty()) {
                bodyHtml.append(getMsg("msg.no.comments", locale));
            } else {
                bodyHtml.append("<ul>");
                for (String c : comments) {
                    // Stored XSS sink: stored comment rendered without encoding into response
                    bodyHtml.append("<li>" + c + "</li>");
                }
                bodyHtml.append("</ul>");
            }
            bodyHtml.append("<br>");
            bodyHtml.append(getInfoMsg("msg.note.stored.xss", locale));

            responseToClient(req, res, getMsg("title.stored.xss.page", locale), bodyHtml.toString());

        } catch (Exception e) {
            log.error("Exception occurs: ", e);
        }
    }
}
