#include <rlib/rnet.h>

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

RTEST (rhttp, negative_content_length, RTEST_FAST)
{
  static const rchar req_str[] =
      "GET / HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n";
  RHttpRequest * req;
  RHttpError err;
  RBuffer * buf;

  r_assert_cmpptr ((buf = r_buffer_new_dup (R_STR_WITH_SIZE_ARGS (req_str))), !=, NULL);
  r_assert_cmpptr ((req = r_http_request_new_from_buffer (buf, &err, NULL)), !=, NULL);
  r_buffer_unref (buf);

  /* A negative Content-Length must not be taken as a (negative) body
   * size -- it is rejected, leaving no body. */
  r_assert_cmpint (r_http_request_calc_body_size (req, NULL), ==, 0);

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
  r_assert_cmpbufsize (orig, 0, -1, ==, buf, 0, -1);

  r_buffer_unref (buf);
  r_buffer_unref (orig);
  r_http_request_unref (req);
}
RTEST_END;

RTEST (rhttp, body_buffer, RTEST_FAST)
{
  RHttpRequest * req;
  RBuffer * buf;

  r_assert_cmpptr ((req = r_http_request_new (R_HTTP_METHOD_GET,
          "http://github.com/ieei/rlib", NULL, NULL)), !=, NULL);
  r_assert_cmpptr ((buf = r_http_request_get_body_buffer (req)), ==, NULL);

  r_assert_cmpptr ((buf = r_buffer_new_dup (R_STR_WITH_SIZE_ARGS ("foobar"))), !=, NULL);
  r_assert_cmpint (r_http_request_set_body_buffer (req, buf), ==, R_HTTP_OK);
  r_buffer_unref (buf);

  r_assert_cmpptr ((buf = r_http_request_get_buffer (req)), !=, NULL);
  r_assert_cmpbufsstr (buf, 0, -1, ==, "GET /ieei/rlib HTTP/1.1\r\nHost: github.com\r\n\r\nfoobar");
  r_buffer_unref (buf);

  r_assert_cmpptr ((buf = r_buffer_new_dup (R_STR_WITH_SIZE_ARGS ("\n1337"))), !=, NULL);
  r_assert_cmpint (r_http_request_set_body_buffer (req, buf), ==, R_HTTP_OK);
  r_buffer_unref (buf);

  r_assert_cmpptr ((buf = r_http_request_get_buffer (req)), !=, NULL);
  r_assert_cmpbufsstr (buf, 0, -1, ==, "GET /ieei/rlib HTTP/1.1\r\nHost: github.com\r\n\r\n\n1337");
  r_buffer_unref (buf);

  r_assert_cmpint (r_http_request_set_body_buffer (req, NULL), ==, R_HTTP_OK);
  r_assert_cmpptr ((buf = r_http_request_get_buffer (req)), !=, NULL);
  r_assert_cmpbufsstr (buf, 0, -1, ==, "GET /ieei/rlib HTTP/1.1\r\nHost: github.com\r\n\r\n");
  r_buffer_unref (buf);

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
  r_assert_cmpptr ((buf = r_buffer_new_dup (http_200_response, 42)), !=, NULL);
  r_assert_cmpptr ((res = r_http_response_new_from_buffer (NULL, buf, &err, &next)), ==, NULL);
  r_buffer_unref (buf);
  r_assert_cmpint (err, ==, R_HTTP_BUF_TOO_SMALL);

  r_assert_cmpptr ((buf = r_buffer_new_dup (R_STR_WITH_SIZE_ARGS (http_200_response))), !=, NULL);
  r_assert_cmpptr ((res = r_http_response_new_from_buffer (NULL, buf, &err, &next)), !=, NULL);
  r_buffer_unref (buf);
  r_assert_cmpptr (next, !=, NULL);

  r_assert_cmpint (r_http_response_get_status (res), ==, R_HTTP_STATUS_OK);

  r_assert_cmpstr ((tmp = r_http_response_get_header (res, "content-length", -1)), ==, "1270"); r_free (tmp);
  r_assert_cmpuint (r_http_response_calc_body_size (res, NULL), ==, 1270);
  r_assert_cmpuint (r_buffer_get_size (next), ==, 1270);
  r_assert_cmpint (r_http_response_set_body_buffer (res, next), ==, R_HTTP_OK);
  r_buffer_unref (next);

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
  r_assert_cmpbufsstr (buf, 0, -1, ==, http_200_ok);
  r_buffer_unref (buf);
  r_http_response_unref (res);

  r_assert_cmpptr ((res = r_http_response_new (NULL,
          R_HTTP_STATUS_NOT_FOUND, NULL, NULL, NULL)), !=, NULL);
  r_assert_cmpint (r_http_response_get_status (res), ==, R_HTTP_STATUS_NOT_FOUND);
  r_assert_cmpptr ((buf = r_http_request_get_buffer (res)), !=, NULL);
  r_assert_cmpbufsstr (buf, 0, -1, ==, http_404_not_found);
  r_buffer_unref (buf);
  r_http_response_unref (res);
}
RTEST_END;

RTEST (rhttp, response_add_header, RTEST_FAST)
{
  RBuffer * buf;
  RHttpResponse * res;
  static const rchar expected[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 42\r\n"
    "\r\n";

  r_assert_cmpptr ((res = r_http_response_new (NULL,
          R_HTTP_STATUS_OK, "OK", NULL, NULL)), !=, NULL);
  r_http_response_add_header (res, "Content-Type", -1, "text/html", -1);
  r_http_response_add_header (res, "Content-Length", -1, "42", -1);

  r_assert_cmpptr ((buf = r_http_request_get_buffer (res)), !=, NULL);
  r_assert_cmpbufsstr (buf, 0, -1, ==, expected);
  r_buffer_unref (buf);
  r_http_response_unref (res);
}
RTEST_END;

RTEST (rhttp, response_set_body_buffer_full, RTEST_FAST)
{
  RBuffer * buf;
  RHttpResponse * res;
  static const rchar body[] =
    "<html>\n"
    " <head><title>Test</title></head>\n"
    " <body></body>\n"
    "</html>\n";
  static const rchar expected[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 64\r\n"
    "\r\n"
    "<html>\n"
    " <head><title>Test</title></head>\n"
    " <body></body>\n"
    "</html>\n";

  r_assert_cmpptr ((res = r_http_response_new (NULL,
          R_HTTP_STATUS_OK, "OK", NULL, NULL)), !=, NULL);
  r_assert_cmpptr ((buf = r_buffer_new_dup (R_STR_WITH_SIZE_ARGS (body))), !=, NULL);
  r_assert_cmpint (r_http_response_set_body_buffer_full (res, buf,
        R_STR_WITH_SIZE_ARGS ("text/html"), TRUE), ==, R_HTTP_OK);
  r_buffer_unref (buf);

  r_assert_cmpptr ((buf = r_http_request_get_buffer (res)), !=, NULL);
  r_assert_cmpbufsstr (buf, 0, -1, ==, expected);
  r_buffer_unref (buf);
  r_http_response_unref (res);
}
RTEST_END;

/* TODO: Add tests for various request->reponse patterns! */


static const rchar http_hdr_response[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-Type: text/html\r\n"
  "Content-Length: 5\r\n"
  "Set-Cookie: a=1\r\n"
  "Set-Cookie: b=2\r\n"
  "Connection: keep-alive, Upgrade\r\n"
  "\r\n"
  "hello";

RTEST (rhttp, header_lookup_anchored, RTEST_FAST)
{
  RHttpResponse * res;
  RHttpError err;
  RBuffer * buf;
  rchar * tmp;

  r_assert_cmpptr ((buf = r_buffer_new_dup (R_STR_WITH_SIZE_ARGS (http_hdr_response))), !=, NULL);
  r_assert_cmpptr ((res = r_http_response_new_from_buffer (NULL, buf, &err, NULL)), !=, NULL);
  r_buffer_unref (buf);

  /* Whole-name match (case-insensitive). */
  r_assert_cmpstr ((tmp = r_http_response_get_header (res, "Content-Type", -1)), ==, "text/html"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_http_response_get_header (res, "content-length", -1)), ==, "5"); r_free (tmp);
  r_assert (r_http_response_has_header (res, "Content-Length", -1));

  /* A field name that is only a suffix of another header must NOT match. */
  r_assert_cmpptr ((tmp = r_http_response_get_header (res, "Type", -1)), ==, NULL);
  r_assert_cmpptr ((tmp = r_http_response_get_header (res, "Length", -1)), ==, NULL);
  r_assert (!r_http_response_has_header (res, "Type", -1));
  r_assert (!r_http_response_has_header (res, "Length", -1));

  /* Value match within a comma list, case-insensitive. */
  r_assert (r_http_response_has_header_of_value (res, "Connection", -1, "keep-alive", -1));
  r_assert (r_http_response_has_header_of_value (res, "Connection", -1, "upgrade", -1));
  r_assert (!r_http_response_has_header_of_value (res, "Connection", -1, "close", -1));

  r_http_response_unref (res);
}
RTEST_END;

typedef struct {
  ruint count;
  ruint cookies;
  ruint stop_at;
} RTestHdrCtx;

static rboolean
r_test_hdr_count (rpointer data, const rchar * name, rsize nsize,
    const rchar * value, rsize vsize)
{
  RTestHdrCtx * ctx = data;
  (void) value; (void) vsize;

  ctx->count++;
  if (nsize == 10 && r_strncasecmp (name, "Set-Cookie", 10) == 0)
    ctx->cookies++;
  return ctx->stop_at == 0 || ctx->count < ctx->stop_at;
}

RTEST (rhttp, header_foreach, RTEST_FAST)
{
  RHttpResponse * res;
  RHttpError err;
  RBuffer * buf;
  RTestHdrCtx ctx = { 0, 0, 0 };

  r_assert_cmpptr ((buf = r_buffer_new_dup (R_STR_WITH_SIZE_ARGS (http_hdr_response))), !=, NULL);
  r_assert_cmpptr ((res = r_http_response_new_from_buffer (NULL, buf, &err, NULL)), !=, NULL);
  r_buffer_unref (buf);

  /* Enumerate all headers in order, including the repeated Set-Cookie. */
  r_http_response_foreach_header (res, r_test_hdr_count, &ctx);
  r_assert_cmpuint (ctx.count, ==, 5);
  r_assert_cmpuint (ctx.cookies, ==, 2);

  /* Returning FALSE stops the walk. */
  ctx.count = ctx.cookies = 0;
  ctx.stop_at = 2;
  r_http_response_foreach_header (res, r_test_hdr_count, &ctx);
  r_assert_cmpuint (ctx.count, ==, 2);

  r_http_response_unref (res);
}
RTEST_END;

static rboolean
r_test_hdr_count_named (rpointer data, const rchar * name, rsize nsize,
    const rchar * value, rsize vsize)
{
  ruint * matches = ((rpointer *) data)[0];
  const rchar * target = ((rpointer *) data)[1];
  (void) value; (void) vsize;
  if (nsize == r_strlen (target) && r_strncasecmp (name, target, nsize) == 0)
    (*matches)++;
  return TRUE;
}


static ruint
r_test_count_header (RHttpResponse * res, const rchar * field)
{
  ruint matches = 0;
  rpointer ctx[2];
  ctx[0] = &matches;
  ctx[1] = (rpointer) field;
  r_http_response_foreach_header (res, r_test_hdr_count_named, ctx);
  return matches;
}

RTEST (rhttp, header_set_remove, RTEST_FAST)
{
  RHttpResponse * res;
  rchar * tmp;

  r_assert_cmpptr ((res = r_http_response_new (NULL, R_HTTP_STATUS_OK,
          NULL, NULL, NULL)), !=, NULL);

  /* set replaces an existing header rather than duplicating it. */
  r_assert (r_http_response_add_header (res, "X-Test", -1, "one", -1));
  r_assert (r_http_response_set_header (res, "X-Test", -1, "two", -1));
  r_assert_cmpuint (r_test_count_header (res, "X-Test"), ==, 1);
  r_assert_cmpstr ((tmp = r_http_response_get_header (res, "X-Test", -1)), ==, "two");
  r_free (tmp);

  /* set on an absent header adds it. */
  r_assert (r_http_response_set_header (res, "X-New", -1, "v", -1));
  r_assert_cmpstr ((tmp = r_http_response_get_header (res, "X-New", -1)), ==, "v");
  r_free (tmp);

  /* remove drops every instance and reports whether anything was removed. */
  r_assert (r_http_response_add_header (res, "X-Dup", -1, "a", -1));
  r_assert (r_http_response_add_header (res, "X-Dup", -1, "b", -1));
  r_assert_cmpuint (r_test_count_header (res, "X-Dup"), ==, 2);
  r_assert (r_http_response_remove_header (res, "X-Dup", -1));
  r_assert_cmpuint (r_test_count_header (res, "X-Dup"), ==, 0);
  r_assert (!r_http_response_remove_header (res, "X-Dup", -1));

  /* the untouched headers survive. */
  r_assert_cmpuint (r_test_count_header (res, "X-Test"), ==, 1);
  r_assert_cmpuint (r_test_count_header (res, "X-New"), ==, 1);

  r_http_response_unref (res);
}
RTEST_END;

RTEST (rhttp, set_body_no_duplicate_content_length, RTEST_FAST)
{
  RHttpResponse * res;
  RBuffer * b1, * b2;
  rchar * tmp;

  r_assert_cmpptr ((res = r_http_response_new (NULL, R_HTTP_STATUS_OK,
          NULL, NULL, NULL)), !=, NULL);
  r_assert_cmpptr ((b1 = r_buffer_new_dup ("ab", 2)), !=, NULL);
  r_assert_cmpptr ((b2 = r_buffer_new_dup ("xyz", 3)), !=, NULL);

  /* Re-setting the body must overwrite Content-Length, not add a second. */
  r_http_response_set_body_buffer_full (res, b1, "text/plain", -1, TRUE);
  r_http_response_set_body_buffer_full (res, b2, "text/plain", -1, TRUE);

  r_assert_cmpuint (r_test_count_header (res, "Content-Length"), ==, 1);
  r_assert_cmpuint (r_test_count_header (res, "Content-Type"), ==, 1);
  r_assert_cmpstr ((tmp = r_http_response_get_header (res, "Content-Length", -1)), ==, "3");
  r_free (tmp);

  r_buffer_unref (b1);
  r_buffer_unref (b2);
  r_http_response_unref (res);
}
RTEST_END;
