0. How a route runs -- the one thing to know
handle_request() runs as a coroutine on the thread that owns the client's socket. That thread also serves thousands of other connections, so a route must never block it. It does not have to think about this as long as it waits only through the calls below, each of which parks the route and lets the worker serve other connections until the wait is over:

https_request() / http_request()                     upstream HTTP calls to other servers
co_mysql_query() / co_mysql_real_query() / co_mysql_store_result()   database
connect_db()                                          may wait for a pooled connection (USE_DATABASE 1)
co_sleep_ms(ms)                                       instead of sleep() / usleep()
co_offload(fn, arg)                                   any other blocking library call: fn(arg) runs on a helper thread, the route continues when it returns
co_mutex_t / co_mutex_lock() / co_mutex_unlock()      a lock you hold across any of the above (a pthread mutex held across them deadlocks the worker)

Do not call sleep(), blocking connect()/read()/write(), getaddrinfo(), mysql_query() or a pthread lock around the calls above. Keep large buffers on the heap (malloc), not on the stack: a route's stack is 256 KB. Responses say "Connection: keep-alive"; the engine rewrites it to "close" when the connection must close, so the route never decides that.

1. Request Data (Request *req)
The Request struct gives you everything parsed from the incoming HTTP request.

req->method: An enum representing the HTTP method (M_GET, M_POST, M_PUT, M_DELETE, M_OPTIONS, etc.).
req->uri: A C-string of the requested path (e.g., "/login" or "/api/data").
req->query: A C-string of the URL query string (everything after the ?), or NULL if none.
req->body: A C-string containing the raw request body.
req->body_len: The length of the request body in bytes.
req->ip: A C-string of the client's IPv4 address.
req->is_tls: Boolean (1 or 0) indicating if this request arrived over HTTPS or HTTP.
2. Header Parsing
char *get_header(Request *req, const char *name) Fetches the value of an HTTP header. Returns NULL if the header is not present.
char *get_header_default(Request *req, const char *name, char *fallback) Fetches an HTTP header, but returns your provided fallback string instead of NULL if the header is missing. (e.g., get_header_default(req, "Host", domain);).
3. Sending Responses
Because this is an epoll-based server, you do not write directly to blocking sockets. Instead, you build your response buffer and queue it to the connection state machine.

int out_append(conn_t *c, const void *data, size_t len) Appends data (like your HTTP headers and body) to the outbound buffer for this connection. You usually format your HTTP response into a malloc'd buffer or stack array using sprintf, and then pass it to out_append.
4. Database (MySQL) -- optional
The server links against libmysqlclient. Connections come from a pool that exists only when USE_DATABASE is 1 in main.c.

MYSQL *connect_db() Takes a connection from the pool, reset to a clean session. Returns NULL if none could be had (the route should answer 500). Important: Always call db_release(conn) before you return from handle_request -- never mysql_close() a pooled connection.
Queries that talk to the server have a co_ twin that runs on a helper thread while your route waits (see section 0):
co_mysql_query(conn, "SELECT ...")        instead of mysql_query
co_mysql_real_query(conn, q, len)         instead of mysql_real_query
co_mysql_store_result(conn)               instead of mysql_store_result
Everything that works on data already fetched is unchanged: mysql_fetch_row, mysql_num_rows, mysql_free_result, mysql_error, mysql_errno, mysql_insert_id, mysql_real_escape_string.
If your route makes a long upstream call and does not need the database during it, db_release(conn) before the call and connect_db() again after it: the pool is shared by every request in flight.
All of this needs USE_DATABASE 1 at the top of main.c (and real credentials in DB_*). With USE_DATABASE 0, connect_db() returns NULL and nothing is connected.
5. File System & Static Assets
FileInfo get_file(const char *host, const char *filename) Reads a file from the disk into memory. Returns a FileInfo struct which has size_t size and char *data. If data is NULL, the file wasn't found.
const char *get_mime_type(const char *filename) Helper that looks at the file extension and returns the appropriate Content-Type string (e.g., "application/json", "text/html").
int is_file_allowed(const char *home, const char *host, const char *uri) Security helper to verify that a requested URI doesn't attempt a path-traversal attack out of the allowed web root.
6. Authentication & Security
void random_string(char *out, size_t len) Generates a random alphanumeric string of length len (rand()-based: fine for ids, not for secrets).
7. External API Calls
Response https_request(const char *hostname, const char *req, int timeout_s) Sends an HTTPS request to an external server on a fresh connection and reads the whole reply. timeout_s bounds the entire exchange; pass HTTP_TIMEOUT_DEFAULT (60 s by default; set it to about three times your slowest upstream -- the guard is for a stuck call, not a slow one). A call without the timeout argument still compiles and gets the default. Returns a Response struct containing .headers, .body, and .status (status "" and body NULL on failure or timeout). You must call free_response(res) when you are done with it. Your route waits for the reply without blocking the worker (section 0).
Response http_request(const char *host, int port, const char *req, int timeout_s) The plain-HTTP sibling, same rules (status "-1" on failure).
void free_response(Response res) Frees the memory allocated inside the Response structs returned by the functions above.
8. JSON Handling
The project includes the cJSON library textually (cJSON.h & cJSON.c). You have full access to its API inside handle_request for reading or creating JSON payloads:

cJSON_Parse(const char *value)
cJSON_CreateObject(), cJSON_AddStringToObject(), cJSON_AddNumberToObject()
cJSON_PrintUnformatted()
cJSON_Delete() (Remember to free JSON objects when done).
Typical Pattern for Expanding Routes
When you add a new route in handle_request, it typically looks like this:

c


if (strcmp(req->uri, "/api/my_new_route") == 0) {
    if (req->method == M_POST) {
        // 1. Process req->body
        // 2. Connect to DB: MYSQL *conn = connect_db();
        // 3. Do logic / queries: co_mysql_query(conn, ...), co_mysql_store_result(conn), ...
        
        // 4. Build response
        char *body = "{\"status\": \"ok\"}";
        char res_buffer[1024];
        sprintf(res_buffer, 
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %zu\r\n"
            "Connection: keep-alive\r\n\r\n"     // always keep-alive; the engine
            "%s", strlen(body), body);               // rewrites it to close when it must
            
        // 5. Send it back
        out_append(c, res_buffer, strlen(res_buffer));
        
        // 6. Cleanup
        // db_release(conn);
        return;
    }
}