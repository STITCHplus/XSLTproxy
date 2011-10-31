/*

    Copyright (c) 2011-2012 KB, Koninklijke Bibliotheek.

    Maintainer : Willem Jan Faber
    Requestor : Theo van Veen

    XSLTproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    tpxslt is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with XSLTproxy. If not, see <http://www.gnu.org/licenses/>.

*/

package tpxslt;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.*;
import java.io.IOException;
import java.io.FileInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.io.StringReader;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.InputStream;
import java.io.Writer;
import java.io.File;
import java.io.PrintWriter;


import java.util.Hashtable;
import java.util.Enumeration;
import java.util.Properties;

import java.net.URL;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.UnknownHostException;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.log4j.Logger;
import org.apache.log4j.BasicConfigurator;

public class tpxslt extends HttpServlet {

    public static final long serialVersionUID = 1L;

    final private static String RESPONSE_HEADER = "text/html; charset=UTF-8";

    private static Properties config = new Properties();
    private static String config_path = "";

    public Logger log = Logger.getLogger(tpxslt.class);

    private static String baseURL = "";
    private static String [] xsl_whitelist = null;
    private static String [] xml_blacklist = null;
    private static String [] xml_whitelist = null;

    public static String working_for = null;

    public void init() throws ServletException {
        final String CONFIG_PATH = getServletContext().getRealPath("/");
        this.config_path = CONFIG_PATH;

        final String APPLICATION_NAME = getServletContext().getServletContextName();

        BasicConfigurator.configure();
        
        FileInputStream config_file = null;
        File config = new File(CONFIG_PATH+"config.ini");
        
        if (config.canRead()) {
            log.debug("Parsing "+CONFIG_PATH+"config.ini");
            try {
                config_file = new FileInputStream(CONFIG_PATH+"config.ini");
            } catch (java.io.FileNotFoundException e) {
                throw new ServletException(e);
            }

            Properties config_prop = new Properties();

            try {
                config_prop.load((config_file));
            } catch (java.io.IOException e) {
                throw new ServletException(e);
            }
            this.config = config_prop;

            log.debug("Parsing finished");
        } else {
            log.fatal("Error, cannot read "+ CONFIG_PATH + "config.ini" );
        }

        String xsl_whitelist = this.config.getProperty("xsl_whitelist");
        this.xsl_whitelist=xsl_whitelist.split(",");

        String xml_blacklist = this.config.getProperty("xml_blacklist");
        this.xml_blacklist=xml_blacklist.split(",");

        String xml_whitelist = this.config.getProperty("xml_whitelist");
        this.xml_whitelist=xml_whitelist.split(",");

        log.debug("xsl_whitelist " + xsl_whitelist);
        log.debug("xml_blacklist" + xml_blacklist);
        log.debug("xml_whitelist " + xml_whitelist);

        log.debug("Init fase done");
    }


    private String transform(StringBuffer XMLdata, StringBuffer XSLdata, Hashtable paramHash) {
        StringReader XML = new StringReader(XMLdata.toString());
        StringReader XSL = new StringReader(XSLdata.toString());

        StreamSource XMLsource = new StreamSource(XML);
        StreamSource XSLsource = new StreamSource(XSL);

        TransformerFactory tFact = TransformerFactory.newInstance();
        ByteArrayOutputStream out1 = new ByteArrayOutputStream();
        StreamResult out = new StreamResult(out1);
        Writer out2 = new StringWriter();
        out.setWriter(out2);


        try {
            Transformer transformer = tFact.newTransformer(XSLsource);
            setTransformParameters(transformer, paramHash);
            transformer.transform(XMLsource, out);

        } catch (Exception e) {
            log.debug(this.working_for + " : " + e.getCause());
            return(e.toString());
        }
        return(out2.toString());
    }


    private StringBuffer getXMLdata(String XMLuri)
    throws MalformedURLException {

        // IP's defined in the .ini file are not allowed to act as XML source. (blacklist)
        // The remote response content header must be set to xml, otherwise the request will not result in a transformation.

        URL url = new URL("http://localhost/index.html");
        StringBuffer result = new StringBuffer ("Error!");
        Boolean allowed = true;
        final String bomChar = "\uFEFF";

        try {
            url = new URL(XMLuri);
        } catch(MalformedURLException e) {
            result.append(" Invalid XML uri!");
            return(result);
        }

        String reqHostIp="";
        //to prevent URL Obfuscation, first get the real IP addr that is requested, then check the blacklist
        try {
            InetAddress resolve = InetAddress.getByName(url.getHost());
            reqHostIp=resolve.getHostAddress();
        } catch (UnknownHostException e) { 
            result.append("The given XML uri is not allowed!");
            return(result); 
        } 

        for (int i = 0; i<this.xml_blacklist.length; i++) {
            String hostIP = new String (this.xml_blacklist[i].trim().substring(1, this.xml_blacklist[i].trim().length()-1));
            if (reqHostIp.startsWith(hostIP)) {
                allowed=false;
            }
        }

        if ( allowed != true ) {
            for (int i = 0; i<this.xml_whitelist.length; i++) {
                String uri = new String (this.xml_whitelist[i].trim().substring(1, this.xml_whitelist[i].trim().length()-1));
                log.debug(uri);
                if (XMLuri.startsWith(uri)) {
                    allowed=true;
                }
           } 
        }

        if ( allowed != true ) {
            result.append(" The given XML uri is not allowed!");
            log.debug(this.working_for+ " : Tried an XML source that is on the XML source blacklist : " + XMLuri);
            return(result);
        }

        try {
            URLConnection con = url.openConnection();
            con.connect();
            String remoteContentType = con.getContentType();
            log.fatal("'"+remoteContentType+"'");
            if (remoteContentType == null) {
                remoteContentType = "xml";
            }
            if ( remoteContentType.toLowerCase().indexOf("xml") < 0 ) {
                result.append(" The content type of the given XML paramerter is not XML.");
                return(result);
            } else {
                result = new StringBuffer ("");
                InputStream inputStream = con.getInputStream();
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream, "UTF8"));
                String line = bufferedReader.readLine();
                int i = 0;
                while (line != null) {
                    Character c = null;
                    try {
                        c = line.charAt(0);
                    } catch (StringIndexOutOfBoundsException e) { }

                    if ( i == 0 && Character.getType(c) == 16 ) {
                        result.append("<?xml version='1.0' encoding='utf-8'?>");
                        line = bufferedReader.readLine();
                    } else {
                        result.append(line);
                        line = bufferedReader.readLine();
                        i = i + 1;
                    }
                }
                bufferedReader.close();
            }
        } catch (IOException e) { }

        if ( result.length() == 0 ) {
            this.log.debug(this.working_for + " : No data from sru source : "+ url);
        } else {
            this.log.debug(this.working_for + " : Done getting data from source : "+ url);
        }

        return(result);
    }

    private StringBuffer getXSLdata(String XSLuri) 
    throws MalformedURLException {

        // XSL template's may only come from hosts defined in the .ini file. (Whitelist)
        
        URL url = new URL("http://www.gnu.org/");  // Java want's me to set some host.
        StringBuffer result = new StringBuffer ("Error!");  
        Boolean allowed = false;

        try {
            url = new URL(XSLuri);

        } catch(MalformedURLException e) {
            result.append(" No valid XSL uri!");
            return(result);
        }

        for (int i = 0; i<this.xsl_whitelist.length; i++) {
            String FQDN = new String (this.xsl_whitelist[i].trim().substring(1, this.xsl_whitelist[i].trim().length()-1));
            result.append(XSLuri+"\n<br>");
            result.append(FQDN+"\n<br>");
            if (XSLuri.startsWith(FQDN)) {
                allowed = true; 
            } 
        }

        if ( allowed != true ) {
            result.append(" The specified XSL uri is not allowed!");
            return(result);
        } 

        result = new StringBuffer ("");
        try {
           BufferedReader in = new BufferedReader(new InputStreamReader(url.openStream(), "UTF8"));
           String readin;
           while ((readin = in.readLine()) != null) {
                result.append(readin); 
            } 
        } catch (MalformedURLException e) { } catch (IOException e) { } //and also catch some fish, while your at it.

        if ( result.length() == 0 ) {
                this.log.debug(this.working_for + " : No data from sru source : "+ url);
            } else {
                this.log.debug(this.working_for + " : Done getting data from source : "+ url);
            }
        return(result);
    }


    private void setTransformParameters(Transformer transformer, Hashtable paramHash) {
        for (Enumeration e = paramHash.keys(); e.hasMoreElements();) {
            String parameter = (String) e.nextElement();
            String value = (String) paramHash.get((Object) parameter);
            log.debug(this.working_for+" : Accepting XSLT transform parameter : '" + parameter + "' with value : '"+value+"'" );
            transformer.setParameter(parameter, value);
        }
    }


    public void doGet(HttpServletRequest request, HttpServletResponse response)
    throws IOException, ServletException {

        this.working_for = request.getRemoteAddr();

        String content_type = request.getParameter("content-type");

        String uri = request.getQueryString();

        if ( content_type != null) {
            response.setContentType(content_type);
            uri=uri.replace("content-type="+content_type, "");
        } else {
            response.setContentType(RESPONSE_HEADER);
        }

        PrintWriter out = response.getWriter();


        String XSLuri = "";
        String XMLuri = "";
        String param = "";
        Hashtable paramHash = new Hashtable();

        /*
            Parameter fishing routine might look messy, 
                the convention is as follow's :
                    Any paramater given after the xml= until xsl= will be regarded as a URI for getting XML data, 
                    Any parameter before xml=<value> and after xsl=<value> will be regarded as a paramters for the xsl template.
                    Special paramter content-type will be treated as such.
        */

        if ((uri.indexOf("xml") > -1)  &&  (uri.indexOf("xsl") > -1)) {

            XMLuri=uri.substring((uri.indexOf("xml")+4), (uri.indexOf("xsl")-1)); // Find out where the xsl paramater starts
            XSLuri=request.getParameter("xsl");                                  // Get the xsl location parameter
            param=param+uri.substring(0, uri.indexOf("xml")) + uri.substring(uri.indexOf(XSLuri)+XSLuri.length());  // All the other stuff will be treated as extra transform parameters
            String [] tmp = null;
            if (param.indexOf('&') > -1) {
                tmp=param.split("\\&");
            }
            if ( tmp != null ) {
                for (int i = 0; i<tmp.length; i++) {
                    if (tmp[i].length() > 0) {
                        if (tmp[i].indexOf('=') > -1) {
                            paramHash.put(new String(tmp[i].substring(0, tmp[i].indexOf("="))), new String(tmp[i].substring(tmp[i].indexOf("=")+1) ) );   // Java compiler does not like this, but I do ;)
                        }
                    }
                }
            }
        } else {
            if (uri.indexOf("xml") < 0) {
                XMLuri = null;
            }
            if (uri.indexOf("xsl") < 0) {
                XSLuri = null;
            }
        }

        Boolean quit = false;

        if ((XSLuri == null) || (XMLuri == null )) {
            out.println("No paramaters supplied, redo from start !");
        } else {
            log.error(java.net.URLDecoder.decode(XMLuri));
            StringBuffer XMLdata= new StringBuffer();
            log.error(XMLuri);
            if (XMLuri.indexOf("%20") < 0) {
                XMLdata= getXMLdata(java.net.URLDecoder.decode(XMLuri));
            } else {
                XMLdata= getXMLdata(XMLuri);
            }

            StringBuffer XSLdata= getXSLdata(XSLuri);
            
            if  (XMLdata.toString().startsWith("Error!")) {
                out.println(XMLdata);
                quit  = true;
            }

            if  (XSLdata.toString().startsWith("Error!")) {
                out.println(XSLdata);
                quit  = true;
            }
            
            if ( !quit ) {
                log.debug(this.working_for+ " : XSL parameter : " + XSLuri);
                log.debug(this.working_for+ " : XML parameter : " + XMLuri);
                out.println(transform(XMLdata, XSLdata, paramHash));
            }
        }
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response) 
    throws IOException, ServletException {
            doGet(request, response);
        }
    }
