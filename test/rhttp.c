#include <rlib/rlib.h>

static const rchar http_get_request[] =
  "GET / HTTP/1.1\r\n"
  "Host: example.org\r\n"
  "Connection: keep-alive\r\n"
  "Upgrade-Insecure-Requests: 1\r\n"
  "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36\r\n"
  "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
  "Accept-Encoding: gzip, deflate, sdch\r\n"
  "Accept-Language: en-US,en;q=0.8,nb;q=0.6,sv;q=0.4,da;q=0.2\r\n"
  "\r\n";
static const rchar http_200_response[] =
  "HTTP/1.1 200 OK\r\n"
  "Cache-Control: max-age=604800\r\n"
  "Content-Type: text/html\r\n"
  "Date: Wed, 08 Feb 2017 10:27:29 GMT\r\n"
  "Etag: \"359670651+ident\"\r\n"
  "Expires: Wed, 15 Feb 2017 10:27:29 GMT\r\n"
  "Last-Modified: Fri, 09 Aug 2013 23:54:35 GMT\r\n"
  "Server: ECS (ewr/15BD)\r\n"
  "Vary: Accept-Encoding\r\n"
  "X-Cache: HIT\r\n"
  "Content-Length: 1270\r\n"
  "\r\n"
  "<!doctype html>\n"
  "<html>\n"
  "<head>\n"
  "    <title>Example Domain</title>\n"
  "\n"
  "    <meta charset=\"utf-8\" />\n"
  "    <meta http-equiv=\"Content-type\" content=\"text/html; charset=utf-8\" />\n"
  "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n"
  "    <style type=\"text/css\">\n"
  "    body {\n"
  "        background-color: #f0f0f2;\n"
  "        margin: 0;\n"
  "        padding: 0;\n"
  "        font-family: \"Open Sans\", \"Helvetica Neue\", Helvetica, Arial, sans-serif;\n"
  "        \n"
  "    }\n"
  "    div {\n"
  "        width: 600px;\n"
  "        margin: 5em auto;\n"
  "        padding: 50px;\n"
  "        background-color: #fff;\n"
  "        border-radius: 1em;\n"
  "    }\n"
  "    a:link, a:visited {\n"
  "        color: #38488f;\n"
  "        text-decoration: none;\n"
  "    }\n"
  "    @media (max-width: 700px) {\n"
  "        body {\n"
  "            background-color: #fff;\n"
  "        }\n"
  "        div {\n"
  "            width: auto;\n"
  "            margin: 0 auto;\n"
  "            border-radius: 0;\n"
  "            padding: 1em;\n"
  "        }\n"
  "    }\n"
  "    </style>    \n"
  "</head>\n"
  "\n"
  "<body>\n"
  "<div>\n"
  "    <h1>Example Domain</h1>\n"
  "    <p>This domain is established to be used for illustrative examples in documents. You may use this\n"
  "    domain in examples without prior coordination or asking for permission.</p>\n"
  "    <p><a href=\"http://www.iana.org/domains/example\">More information...</a></p>\n"
  "</div>\n"
  "</body>\n"
  "</html>\n";

RTEST (rhttp, new_GET_request, RTEST_FAST)
{
  RHttpRequest * req;
  RHttpError err;
  rchar * tmp;

  r_assert_cmpptr ((req = r_http_request_new (R_HTTP_METHOD_GET,
          "http://github.com/ieei/rlib", NULL, &err)), !=, NULL);
  r_assert_cmpint (r_http_request_get_method (req), ==, R_HTTP_METHOD_GET);
  r_assert_cmpstr ((tmp = r_http_request_get_header (req, "Host", 4)), ==, "github.com"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_http_request_get_header (req, "host", 4)), ==, "github.com"); r_free (tmp);

  r_http_request_unref (req);
}
RTEST_END;

RTEST (rhttp, new_request_from_buffer, RTEST_FAST)
{
  RHttpRequest * req;
  RHttpError err;
  RBuffer * buf;
  RUri * uri;
  rchar * tmp;

  r_assert_cmpptr ((req = r_http_request_new_from_buffer (NULL, &err, NULL)), ==, NULL);
  r_assert_cmpint (err, ==, R_HTTP_INVAL);

  r_assert_cmpptr ((buf = r_buffer_new_dup (http_get_request, sizeof (http_get_request) - 1)), !=, NULL);
  r_assert_cmpptr ((req = r_http_request_new_from_buffer (buf, &err, NULL)), !=, NULL);
  r_buffer_unref (buf);
  r_assert_cmpint (err, ==, R_HTTP_OK);

  r_assert_cmpint (r_http_request_get_method (req), ==, R_HTTP_METHOD_GET);
  r_assert_cmpptr ((uri = r_http_request_get_uri (req)), !=, NULL);
  r_assert_cmpstr ((tmp = r_uri_get_escaped (uri)), ==, "http://example.org/");
  r_free (tmp);
  r_uri_unref (uri);

  r_assert_cmpstr ((tmp = r_http_request_get_header (req, "Connection", -1)), ==, "keep-alive"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_http_request_get_header (req, "upgrade-insecure-requests", -1)), ==, "1"); r_free (tmp);
  r_assert_cmpptr (r_http_request_get_body_buffer (req), ==, NULL);

  r_http_request_unref (req);
}
RTEST_END;

RTEST (rhttp, request_get_buffer, RTEST_FAST)
{
  RBuffer * orig, * buf;
  RHttpRequest * req;
  RHttpError err;

  r_assert_cmpptr ((orig = r_buffer_new_dup (http_get_request, sizeof (http_get_request) - 1)), !=, NULL);
  r_assert_cmpptr ((req = r_http_request_new_from_buffer (orig, &err, NULL)), !=, NULL);
  r_assert_cmpint (err, ==, R_HTTP_OK);

  r_assert_cmpptr ((buf = r_http_request_get_buffer (req)), !=, NULL);
  r_assert_cmpint (r_buffer_cmp (orig, 0, buf, 0, r_buffer_get_size (buf)), ==, 0);

  r_buffer_unref (buf);
  r_buffer_unref (orig);
  r_http_request_unref (req);
}
RTEST_END;

RTEST (rhttp, new_200_response, RTEST_FAST)
{
  RHttpResponse * res;
  RHttpError err;
  rchar * tmp;

  r_assert_cmpptr ((res = r_http_response_new (NULL,
          R_HTTP_STATUS_OK, "OK", NULL, &err)), !=, NULL);
  r_assert_cmpint (r_http_response_get_status (res), ==, R_HTTP_STATUS_OK);
  r_assert_cmpstr ((tmp = r_http_response_get_phrase (res)), ==, "OK"); r_free (tmp);

  r_http_response_unref (res);
}
RTEST_END;

RTEST (rhttp, new_response_from_buffer, RTEST_FAST)
{
  RHttpResponse * res;
  RHttpError err;
  RBuffer * buf, * next;
  rchar * tmp;

  r_assert_cmpptr ((res = r_http_response_new_from_buffer (NULL, NULL, &err, NULL)), ==, NULL);
  r_assert_cmpint (err, ==, R_HTTP_INVAL);
  r_assert_cmpptr ((buf = r_buffer_new_dup (http_200_response, sizeof (http_200_response) - 42)), !=, NULL);
  r_assert_cmpptr ((res = r_http_response_new_from_buffer (NULL, buf, &err, &next)), ==, NULL);
  r_buffer_unref (buf);
  r_assert_cmpint (err, ==, R_HTTP_BUF_TOO_SMALL);

  r_assert_cmpptr ((buf = r_buffer_new_dup (http_200_response, sizeof (http_200_response) - 1)), !=, NULL);
  r_assert_cmpptr ((res = r_http_response_new_from_buffer (NULL, buf, &err, NULL)), !=, NULL);
  r_buffer_unref (buf);
  r_assert_cmpptr (next, ==, NULL);

  r_assert_cmpint (r_http_response_get_status (res), ==, R_HTTP_STATUS_OK);

  r_assert_cmpstr ((tmp = r_http_response_get_header (res, "content-length", -1)), ==, "1270"); r_free (tmp);
  r_assert_cmpptr ((buf = r_http_response_get_body_buffer (res)), !=, NULL);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, 1270);
  r_buffer_unref (buf);

  r_http_response_unref (res);
}
RTEST_END;

RTEST (rhttp, response_get_buffer, RTEST_FAST)
{
  RBuffer * buf;
  RHttpResponse * res;
  static const rchar http_200_ok[] = "HTTP/1.1 200 OK\r\n\r\n";
  static const rchar http_404_not_found[] = "HTTP/1.1 404 Not Found\r\n\r\n";

  r_assert_cmpptr ((res = r_http_response_new (NULL,
          R_HTTP_STATUS_OK, "OK", NULL, NULL)), !=, NULL);
  r_assert_cmpint (r_http_response_get_status (res), ==, R_HTTP_STATUS_OK);
  r_assert_cmpptr ((buf = r_http_request_get_buffer (res)), !=, NULL);
  r_assert_cmpint (r_buffer_memcmp (buf, 0, R_STR_WITH_SIZE_ARGS (http_200_ok)), ==, 0);
  r_buffer_unref (buf);
  r_http_response_unref (res);

  r_assert_cmpptr ((res = r_http_response_new (NULL,
          R_HTTP_STATUS_NOT_FOUND, NULL, NULL, NULL)), !=, NULL);
  r_assert_cmpint (r_http_response_get_status (res), ==, R_HTTP_STATUS_NOT_FOUND);
  r_assert_cmpptr ((buf = r_http_request_get_buffer (res)), !=, NULL);
  r_assert_cmpint (r_buffer_memcmp (buf, 0, R_STR_WITH_SIZE_ARGS (http_404_not_found)), ==, 0);
  r_buffer_unref (buf);
  r_http_response_unref (res);
}
RTEST_END;

/* TODO: Add tests for various request->reponse patterns! */

