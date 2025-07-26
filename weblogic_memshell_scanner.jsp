<%@ page import="java.util.*,
                 javax.servlet.*,
                 java.io.*,
                 javax.xml.parsers.*,
                 org.w3c.dom.*,
                 java.lang.reflect.Field,
                 java.lang.reflect.Method,
                 java.net.URLDecoder" %>
<%@ page contentType="text/html; charset=UTF-8" %>
<%!
    // =================================================================================================
    // Helper method to safely get a field value using reflection
    // =================================================================================================
    private Object getFieldValue(Object obj, String fieldName) {
        try {
            Field field = obj.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            return field.get(obj);
        } catch (Exception e) {
            // Field not found in this class, check superclass
            try {
                Field field = obj.getClass().getSuperclass().getDeclaredField(fieldName);
                field.setAccessible(true);
                return field.get(obj);
            } catch (Exception ex) {
                // Still not found, return null
                return null;
            }
        }
    }
%>
<html>
<head>
    <title>WebLogic Memshell Scanner</title>
    <style>
        body { font-family: Consolas, Monaco, monospace; background-color: #1e1e1e; color: #d4d4d4; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: auto; background: #252526; padding: 20px; border: 1px solid #333; box-shadow: 0 0 15px rgba(0,0,0,0.5); }
        h2, h3 { color: #4ec9b0; border-bottom: 1px solid #4ec9b0; padding-bottom: 5px; }
        .info { color: #9cdcfe; }
        .warn { color: #ffd700; }
        .suspicious { color: #f44747; font-weight: bold; }
        pre { background: #1e1e1e; padding: 15px; border: 1px solid #3c3c3c; white-space: pre-wrap; word-wrap: break-word; font-size: 14px; line-height: 1.5; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 10px; text-align: left; border: 1px solid #3c3c3c; }
        th { background-color: #007acc; color: #fff; }
        tr:nth-child(even) { background-color: #2d2d2d; }
    </style>
</head>
<body>
<div class="container">
    <h2>WebLogic Memshell Scanner (JSP Edition)</h2>
    <p class="info">Scanning application: <strong><%= application.getServletContextName() %></strong></p>
    <hr>

<%
    try {
        ServletContext context = request.getServletContext();
        Set<String> declaredFilters = new HashSet<>();
        Set<String> declaredServlets = new HashSet<>();

        // =================================================================================================
        // 1. Parse web.xml and weblogic.xml to get declared components
        // =================================================================================================
        out.println("<h3>[1] Parsing Configuration Files</h3>");
        String webXmlPath = context.getRealPath("/WEB-INF/web.xml");
        String weblogicXmlPath = context.getRealPath("/WEB-INF/weblogic.xml");

        if (new File(webXmlPath).exists()) {
            out.println("<p class='info'>Found web.xml: " + webXmlPath + "</p>");
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document doc = dBuilder.parse(webXmlPath);
            doc.getDocumentElement().normalize();

            NodeList filterNodes = doc.getElementsByTagName("filter");
            for (int i = 0; i < filterNodes.getLength(); i++) {
                Element element = (Element) filterNodes.item(i);
                declaredFilters.add(element.getElementsByTagName("filter-name").item(0).getTextContent());
            }

            NodeList servletNodes = doc.getElementsByTagName("servlet");
            for (int i = 0; i < servletNodes.getLength(); i++) {
                Element element = (Element) servletNodes.item(i);
                declaredServlets.add(element.getElementsByTagName("servlet-name").item(0).getTextContent());
            }
        } else {
            out.println("<p class='warn'>Warning: web.xml not found. Analysis will be based on runtime components only.</p>");
        }
        
        // weblogic.xml is less common for this but good to check
        if (new File(weblogicXmlPath).exists()) {
             out.println("<p class='info'>Found weblogic.xml: " + weblogicXmlPath + "</p>");
        }

        out.println("<p><strong>Declared Filters:</strong> " + declaredFilters + "</p>");
        out.println("<p><strong>Declared Servlets:</strong> " + declaredServlets + "</p>");

        // =================================================================================================
        // 2. Analyze Runtime Filters
        // =================================================================================================
        out.println("<h3>[2] Analyzing Runtime Filters</h3>");
        out.println("<table><tr><th>Status</th><th>Filter Name</th><th>Filter Class</th><th>URL Mappings</th><th>ClassLoader</th></tr>");

        try {
            // Modern Way (Servlet 3.0+)
            Map<String, ? extends FilterRegistration> filterRegistrations = context.getFilterRegistrations();
            for (String filterName : filterRegistrations.keySet()) {
                FilterRegistration registration = filterRegistrations.get(filterName);
                boolean isDeclared = declaredFilters.contains(filterName);
                String status = isDeclared ? "<span class='info'>DECLARED</span>" : "<span class='suspicious'>SUSPICIOUS (Not in web.xml)</span>";
                out.println("<tr><td>" + status + "</td><td>" + filterName + "</td><td>" + registration.getClassName() + "</td><td>" + registration.getUrlPatternMappings() + "</td><td>" + registration.getClass().getClassLoader().toString().replace("<", "&lt;").replace(">", "&gt;") + "</td></tr>");
            }
        } catch (NoSuchMethodError e) {
            // Fallback for Older WebLogic (Servlet 2.5) using Reflection
            out.println("<tr><td colspan='5' class='warn'>Servlet 3.0 API not found. Falling back to reflection for WebLogic 10.x...</td></tr>");
            Object webappContext = context;
            Object filterManager = getFieldValue(webappContext, "filterManager");
            if (filterManager != null) {
                Object filterMap = getFieldValue(filterManager, "filterMap"); // This is a Map
                if (filterMap instanceof Map) {
                    for (Object filterName : ((Map) filterMap).keySet()) {
                        Object filterStub = ((Map) filterMap).get(filterName);
                        String className = (String) getFieldValue(filterStub, "className");
                        Object filterInstance = getFieldValue(filterStub, "filter");
                        String classLoaderInfo = filterInstance != null ? filterInstance.getClass().getClassLoader().toString().replace("<", "&lt;").replace(">", "&gt;") : "N/A";
                        
                        boolean isDeclared = declaredFilters.contains(filterName.toString());
                        String status = isDeclared ? "<span class='info'>DECLARED</span>" : "<span class='suspicious'>SUSPICIOUS (Not in web.xml)</span>";
                        out.println("<tr><td>" + status + "</td><td>" + filterName + "</td><td>" + className + "</td><td>(Reflection-based, mappings not easily available)</td><td>" + classLoaderInfo + "</td></tr>");
                    }
                }
            } else {
                 out.println("<tr><td colspan='5' class='warn'>Could not find FilterManager via reflection.</td></tr>");
            }
        }
        out.println("</table>");

        // =================================================================================================
        // 3. Analyze Runtime Servlets
        // =================================================================================================
        out.println("<h3>[3] Analyzing Runtime Servlets</h3>");
        out.println("<table><tr><th>Status</th><th>Servlet Name</th><th>Servlet Class</th><th>Mappings</th><th>ClassLoader</th></tr>");

        try {
            // Modern Way (Servlet 3.0+)
            Map<String, ? extends ServletRegistration> servletRegistrations = context.getServletRegistrations();
            for (String servletName : servletRegistrations.keySet()) {
                ServletRegistration registration = servletRegistrations.get(servletName);
                boolean isDeclared = declaredServlets.contains(servletName) || servletName.startsWith("jsp") || servletName.equals("default");
                String status = isDeclared ? "<span class='info'>DECLARED/DEFAULT</span>" : "<span class='suspicious'>SUSPICIOUS (Not in web.xml)</span>";
                out.println("<tr><td>" + status + "</td><td>" + servletName + "</td><td>" + registration.getClassName() + "</td><td>" + registration.getMappings() + "</td><td>" + registration.getClass().getClassLoader().toString().replace("<", "&lt;").replace(">", "&gt;") + "</td></tr>");
            }
        } catch (NoSuchMethodError e) {
            // Fallback for Older WebLogic (Servlet 2.5) using Reflection
            out.println("<tr><td colspan='5' class='warn'>Servlet 3.0 API not found. Falling back to reflection for WebLogic 10.x...</td></tr>");
            Object webappContext = context;
            Object servletStubs = getFieldValue(webappContext, "servletStubs"); // This is a Map
            if (servletStubs instanceof Map) {
                for (Object servletName : ((Map) servletStubs).keySet()) {
                    Object servletStub = ((Map) servletStubs).get(servletName);
                    String className = (String) getFieldValue(servletStub, "className");
                    Object servletInstance = getFieldValue(servletStub, "servlet");
                    String classLoaderInfo = servletInstance != null ? servletInstance.getClass().getClassLoader().toString().replace("<", "&lt;").replace(">", "&gt;") : "N/A";
                    Collection mappings = (Collection) getFieldValue(servletStub, "urlPatterns");

                    boolean isDeclared = declaredServlets.contains(servletName.toString()) || servletName.toString().startsWith("jsp") || servletName.toString().equals("FileServlet");
                    String status = isDeclared ? "<span class='info'>DECLARED/DEFAULT</span>" : "<span class='suspicious'>SUSPICIOUS (Not in web.xml)</span>";
                    out.println("<tr><td>" + status + "</td><td>" + servletName + "</td><td>" + className + "</td><td>" + mappings + "</td><td>" + classLoaderInfo + "</td></tr>");
                }
            } else {
                out.println("<tr><td colspan'5' class='warn'>Could not find ServletStubs via reflection.</td></tr>");
            }
        }
        out.println("</table>");

    } catch (Exception e) {
        out.println("<h2>An error occurred during scan:</h2>");
        out.println("<pre class='suspicious'>");
        e.printStackTrace(new java.io.PrintWriter(out));
        out.println("</pre>");
    }
%>
</div>
</body>
</html>
