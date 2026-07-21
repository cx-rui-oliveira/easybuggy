package org.t246osslab.easybuggy.vulnerabilities;

import java.io.IOException;
import java.util.Locale;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.t246osslab.easybuggy.core.servlets.AbstractServlet;

@SuppressWarnings("serial")
@WebServlet(urlPatterns = { "/reflected-xss" })
public class ReflectedXSSServlet extends AbstractServlet {

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {

        try {
            String name = req.getParameter("name");
            Locale locale = req.getLocale();

            StringBuilder bodyHtml = new StringBuilder();

            bodyHtml.append("<form action=\"reflected-xss\" method=\"get\">");
            bodyHtml.append(getMsg("description.greet.user", locale));
            bodyHtml.append("<br><br>");
            bodyHtml.append(getMsg("label.your.name", locale) + ": ");
            bodyHtml.append("<input type=\"text\" name=\"name\" size=\"100\" maxlength=\"200\">");
            bodyHtml.append("<br><br>");
            bodyHtml.append("<input type=\"submit\" value=\"" + getMsg("label.submit", locale) + "\">");
            bodyHtml.append("<br><br>");

            if (!StringUtils.isBlank(name)) {
                bodyHtml.append(getMsg("label.greeting", locale) + ", " + name + "!");
            } else {
                bodyHtml.append(getMsg("msg.enter.name", locale));
            }
            bodyHtml.append("<br><br>");
            bodyHtml.append(getInfoMsg("msg.note.reflected.xss", locale));
            bodyHtml.append("</form>");

            responseToClient(req, res, getMsg("title.reflected.xss.page", locale), bodyHtml.toString());

        } catch (Exception e) {
            log.error("Exception occurs: ", e);
        }
    }
}
