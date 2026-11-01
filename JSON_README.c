Your project includes cJSON (v1.7.19), which is a lightweight, widely used C library for parsing and building JSON.

Here is the complete API guide for the JSON functions you can use inside handle_request:

1. Parsing JSON (Reading a Request Body)
When you receive a POST/PUT request with a JSON body (req->body), you parse it into a cJSON object tree.

cJSON *cJSON_Parse(const char *value) Parses a string containing JSON and returns the root cJSON object. Always check if it returned NULL to handle invalid JSON.
void cJSON_Delete(cJSON *item) CRITICAL: You must call this on the root object when you are done to free the memory.
Extracting Data from Objects
Once you have the root object, you can pull values out of it:

cJSON *cJSON_GetObjectItem(const cJSON * const object, const char * const string) Gets a property from a JSON object (case-insensitive). Returns NULL if not found.
cJSON *cJSON_GetObjectItemCaseSensitive(...) Same as above but strictly case-sensitive.
cJSON_bool cJSON_HasObjectItem(const cJSON *object, const char *string) Returns 1 if the key exists, 0 otherwise.
Checking Types & Values
After you get an item using cJSON_GetObjectItem, you should verify its type and read its value:

Type checks:
cJSON_IsString(item)
cJSON_IsNumber(item)
cJSON_IsBool(item) (or cJSON_IsTrue / cJSON_IsFalse)
cJSON_IsNull(item)
cJSON_IsArray(item)
cJSON_IsObject(item)
Getting the C value:
For Strings: item->valuestring (or use cJSON_GetStringValue(item))
For Numbers: item->valueint or item->valuedouble (or use cJSON_GetNumberValue(item))
Working with Arrays
int cJSON_GetArraySize(const cJSON *array) Returns the number of elements in the array.
cJSON *cJSON_GetArrayItem(const cJSON *array, int index) Gets the item at index.
cJSON_ArrayForEach(element, array) A helpful macro to iterate through an array. Example:
c


cJSON *element = NULL;
cJSON_ArrayForEach(element, my_json_array) {
    // do something with element
}
2. Building JSON (Creating a Response)
To send a JSON response, you build a cJSON object tree, convert it to a string, and then delete the tree.

Creating the Root Object/Array
cJSON *cJSON_CreateObject(void) Creates an empty {} JSON object.
cJSON *cJSON_CreateArray(void) Creates an empty [] JSON array.
Adding Properties to an Object (The Easy Way)
These helper functions create a new item and attach it to your object in one step:

cJSON_AddStringToObject(object, "key", "value")
cJSON_AddNumberToObject(object, "key", 42.5)
cJSON_AddBoolToObject(object, "key", 1) (1 = true, 0 = false)
cJSON_AddTrueToObject(object, "key")
cJSON_AddFalseToObject(object, "key")
cJSON_AddNullToObject(object, "key")
For nested objects/arrays:

cJSON *cJSON_AddObjectToObject(object, "key") (Creates {} and attaches it, returning a pointer to the new nested object).
cJSON *cJSON_AddArrayToObject(object, "key") (Creates [] and attaches it, returning a pointer to the new nested array).
Creating Items Manually & Adding to Arrays
cJSON_CreateString("value")
cJSON_CreateNumber(123)
cJSON_CreateBool(1)
cJSON_AddItemToArray(cJSON *array, cJSON *item) (Appends to an array).
cJSON_AddItemToObject(cJSON *object, "key", cJSON *item) (Manual version of the helpers above).
Converting to a String (Serialization)
char *cJSON_PrintUnformatted(const cJSON *item) Converts the JSON tree into a dense string (no spaces/newlines). You must call free() on the returned string when done.
char *cJSON_Print(const cJSON *item) Same as above, but adds spaces and newlines for readability (pretty-print).
Example: Full JSON Flow (Parse -> Logic -> Respond)
c


// 1. Check if the body exists
if (!req->body) return;
// 2. Parse incoming JSON: {"username": "foo"}
cJSON *parsed_body = cJSON_Parse(req->body);
if (parsed_body == NULL) {
    // Handle invalid JSON...
    return;
}
cJSON *username_item = cJSON_GetObjectItemCaseSensitive(parsed_body, "username");
if (cJSON_IsString(username_item)) {
    printf("User requested: %s\n", username_item->valuestring);
}
// 3. Delete the parsed object when done with it
cJSON_Delete(parsed_body);
// ---------------------------------------------------------
// 4. Build a response JSON: {"status": "success", "user_id": 123}
cJSON *res_json = cJSON_CreateObject();
cJSON_AddStringToObject(res_json, "status", "success");
cJSON_AddNumberToObject(res_json, "user_id", 123);
// 5. Convert to string
char *json_string = cJSON_PrintUnformatted(res_json);
// 6. Delete the response object tree (we only need the string now)
cJSON_Delete(res_json);
// 7. Format the HTTP response headers and body
char http_res[1024];
sprintf(http_res, 
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: %zu\r\n"
    "Connection: close\r\n\r\n"
    "%s", strlen(json_string), json_string);
// 8. Send to client
out_append(c, http_res, strlen(http_res));
// 9. Free the JSON string allocated by cJSON_PrintUnformatted
free(json_string);