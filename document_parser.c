#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <time.h>
#include <pthread.h>
#include <ctype.h>
#include <errno.h>
#include <regex.h>
#include <string.h>
#include <curl/curl.h>
#include <cjson/cJSON.h> 
#include <iconv.h>
#include <stdbool.h>

#define DEFAULT_OPENAI_API_KEY ""
#define DEFAULT_WATCH_PATH ""
#define DEFAULT_TEMP_IMAGE_DIR ""

#define OPENAI_API_KEY (getenv("OPENAI_API_KEY") ? getenv("OPENAI_API_KEY") : DEFAULT_OPENAI_API_KEY)
#define WATCH_PATH (getenv("WATCH_PATH") ? getenv("WATCH_PATH") : DEFAULT_WATCH_PATH)
#define TEMP_IMAGE_DIR (getenv("TEMP_IMAGE_DIR") ? getenv("TEMP_IMAGE_DIR") : DEFAULT_TEMP_IMAGE_DIR)

#define MAX_TEXT_LENGTH 3500
#define EVENT_BUF_LEN (1024 * (sizeof(struct inotify_event) + 16))
#define MAX_RETRIES 5
#define RETRY_DELAY 100000  // 100 ms
#define MAX_FILES 1024

// Mutex for synchronizing database access
pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;

// Global database connection
sqlite3 *db = NULL;


// Function prototypes
void parse_txt_file(const char *filepath);
void parse_rtf_file(const char *filepath);
void parse_pdf_file(const char *filepath);
void parse_doc_file(const char *filepath);
int has_valid_extension(const char *filename);
void delete_file(const char *filepath);
void log_message(const char *level, const char *message, ...);
void init_db(sqlite3 **db);
int should_process_file(sqlite3 *db, const char *filename, int file_size_kb);
int save_to_db(sqlite3 *db, const char *filename, const char *text, const char *operation_time, const char *last_modified_time, int file_size_kb);
void sanitize_text(char *text);
char* sanitize_and_validate_text(char *text);
char* call_openai_api(const char *text);

// Structure to hold file path data for thread processing
typedef struct {
    char filepath[1024];
} thread_data_t;

void *process_file(void *arg);

// Structure to manage memory during HTTP response handling
struct MemoryStruct {
    char *memory;
    size_t size;
};


static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    // Use a temporary pointer to avoid memory leak if realloc fails
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (ptr == NULL) {
        printf("not enough memory (realloc returned NULL)\n");
        free(mem->memory);  // Free the previously allocated memory
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

char* parse_openai_response(const char *json_response) {
    cJSON *json = cJSON_Parse(json_response);
    if (json == NULL) {
        fprintf(stderr, "Error parsing JSON\n");
        return NULL;
    }

    cJSON *choices = cJSON_GetObjectItemCaseSensitive(json, "choices");
    if (!cJSON_IsArray(choices)) {
        cJSON_Delete(json);
        return NULL;
    }

    cJSON *first_choice = cJSON_GetArrayItem(choices, 0);
    if (first_choice == NULL) {
        cJSON_Delete(json);
        return NULL;
    }

    cJSON *message = cJSON_GetObjectItemCaseSensitive(first_choice, "message");
    if (!cJSON_IsObject(message)) {
        cJSON_Delete(json);
        return NULL;
    }

    cJSON *content = cJSON_GetObjectItemCaseSensitive(message, "content");
    if (!cJSON_IsString(content)) {
        cJSON_Delete(json);
        return NULL;
    }

    // strdup check to handle potential memory allocation failure
    char *summary = strdup(content->valuestring);
    if (summary == NULL) {
        fprintf(stderr, "Error duplicating content string\n");
        cJSON_Delete(json);
        return NULL;
    }

    cJSON_Delete(json);
    return summary;
}


char* escape_json_string(const char *input) {
    size_t length = strlen(input);
    size_t escaped_length = length * 2 + 1; // Allocate enough space for the escaped string
    char *escaped = malloc(escaped_length);
    if (!escaped) return NULL;  // Return NULL if memory allocation fails

    const char *p = input;
    char *q = escaped;

    while (*p) {
        switch (*p) {
            case '\"': *q++ = '\\'; *q++ = '\"'; break;
            case '\\': *q++ = '\\'; *q++ = '\\'; break;
            case '\b': *q++ = '\\'; *q++ = 'b'; break;
            case '\f': *q++ = '\\'; *q++ = 'f'; break;
            case '\n': *q++ = '\\'; *q++ = 'n'; break;
            case '\r': *q++ = '\\'; *q++ = 'r'; break;
            case '\t': *q++ = '\\'; *q++ = 't'; break;
            default: *q++ = *p; break;
        }
        p++;
    }
    *q = '\0';  // Null-terminate the escaped string
    printf("Escaped string: %s\n", escaped);  // Optional for debugging
    return escaped;  // The caller is responsible for freeing this memory
}


char* call_openai_api(const char *text) {
    CURL *curl;
    CURLcode res;

    struct MemoryStruct chunk;
    chunk.memory = malloc(1);
    if (chunk.memory == NULL) {
        fprintf(stderr, "Failed to allocate memory for chunk\n");
        return NULL;
    }
    chunk.size = 0;

    char truncated_text[MAX_TEXT_LENGTH + 1];
    strncpy(truncated_text, text, MAX_TEXT_LENGTH);
    truncated_text[MAX_TEXT_LENGTH] = '\0';

    char *escaped_text = escape_json_string(truncated_text);
    if (!escaped_text) {
        fprintf(stderr, "Failed to escape JSON string\n");
        free(chunk.memory);  // Make sure to free previously allocated memory
        return NULL;
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.openai.com/v1/chat/completions");

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        char auth_header[256];
        snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", OPENAI_API_KEY);
        headers = curl_slist_append(headers, auth_header);

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        char json_data[4096];
        snprintf(json_data, sizeof(json_data),
            "{\"model\": \"gpt-3.5-turbo\", \"messages\": ["
            "{\"role\": \"system\", \"content\": \"You are an expert text summarizer.\"},"
            "{\"role\": \"user\", \"content\": \"Create a detailed summary or synopsis of the following text in the language of the text: %s\"}]}", 
            escaped_text);

        printf("JSON Payload: %s\n", json_data);

        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        res = curl_easy_perform(curl);

        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            free(chunk.memory);  // Ensure memory is freed in case of failure
            chunk.memory = NULL;
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }

    curl_global_cleanup();
    free(escaped_text);

    if (chunk.memory) {
        char *summary = escape_json_string(parse_openai_response(chunk.memory));
        if (!summary) {
            fprintf(stderr, "Failed to escape summary\n");
            free(chunk.memory);  // Ensure memory is freed if parsing fails
            return NULL;
        }
        free(chunk.memory);  // Free the entire JSON response memory
        return summary;      // Return only the extracted summary
    }

    return NULL;
}



void start_thread_for_file(const char *filepath) {
    pthread_t thread;
    thread_data_t *data = malloc(sizeof(thread_data_t));
    if (data == NULL) {
        fprintf(stderr, "Failed to allocate memory for thread data\n");
        return;
    }
    strcpy(data->filepath, filepath);
    
    if (pthread_create(&thread, NULL, process_file, data) != 0) {
        fprintf(stderr, "Failed to create thread for file processing\n");
        free(data);  // Free memory if thread creation fails
    } else {
        pthread_detach(thread);  // Detach the thread so it can clean up after itself
    }
}

int trace_callback(unsigned int trace_type, void *ctx, void *p, void *x) {
    const char *sql = (const char *)x;
    printf("Executing SQL: %s\n", sql);
    return 0;  // Returns 0 to indicate the trace was handled successfully
}

void open_db(sqlite3 **db) {
    int rc = sqlite3_open("text_extractor.db", db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(*db));
        exit(EXIT_FAILURE);
    }

    // Imposta la modalità di tracciamento per il debugging
    sqlite3_trace_v2(*db, SQLITE_TRACE_STMT, trace_callback, NULL);

    // Forza la codifica UTF-8
    char *errmsg = 0;
    rc = sqlite3_exec(*db, "PRAGMA encoding = 'UTF-8';", 0, 0, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to set UTF-8 encoding: %s\n", errmsg);
        sqlite3_free(errmsg);  // Libera la memoria allocata per i messaggi di errore
        sqlite3_close(*db);    // Assicurati di chiudere il database in caso di errore
        exit(EXIT_FAILURE);
    }

    // Abilita la modalità WAL per una migliore concorrenza
    rc = sqlite3_exec(*db, "PRAGMA journal_mode=WAL;", 0, 0, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to set WAL mode: %s\n", errmsg);
        sqlite3_free(errmsg);
        sqlite3_close(*db);
        exit(EXIT_FAILURE);
    }
    sqlite3_free(errmsg);  // Libera errmsg dopo l'esecuzione con successo
}

void init_db(sqlite3 **db) {
    int rc = sqlite3_open("text_extractor.db", db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(*db));
        exit(EXIT_FAILURE);
    }

    sqlite3_trace_v2(*db, SQLITE_TRACE_STMT, trace_callback, NULL);

    // Force UTF-8 encoding
    char *errmsg = 0;
    rc = sqlite3_exec(*db, "PRAGMA encoding = 'UTF-8';", 0, 0, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to set UTF-8 encoding: %s\n", errmsg);
        sqlite3_free(errmsg);  // Free memory allocated by SQLite for error messages
        sqlite3_close(*db);    // Ensure database is closed in case of error
        exit(EXIT_FAILURE);
    }

    // Enable WAL mode for better concurrency
    rc = sqlite3_exec(*db, "PRAGMA journal_mode=WAL;", 0, 0, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to set WAL mode: %s\n", errmsg);
        sqlite3_free(errmsg);
        sqlite3_close(*db);
        exit(EXIT_FAILURE);
    }
    sqlite3_free(errmsg);  // Make sure to free errmsg after successful execution

    // Create table with additional columns 'imported' and 'resume'
    char *sql = "CREATE TABLE IF NOT EXISTS extracted_text ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "filename TEXT NOT NULL,"
                "text TEXT NOT NULL,"
                "operation_time TEXT NOT NULL,"
                "last_modified_time TEXT NOT NULL,"
                "file_size_kb INTEGER NOT NULL,"
                "imported BOOLEAN NOT NULL DEFAULT 0,"
                "resume TEXT NOT NULL);";
                
    rc = sqlite3_exec(*db, sql, 0, 0, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errmsg);
        sqlite3_free(errmsg);  // Free error message memory
        sqlite3_close(*db);
        exit(EXIT_FAILURE);
    }
    sqlite3_free(errmsg);  // Free errmsg after successful execution

    // Create indexes for better performance
    sql = "CREATE INDEX IF NOT EXISTS idx_filename ON extracted_text(filename);"
          "CREATE INDEX IF NOT EXISTS idx_operation_time ON extracted_text(operation_time);"
          "CREATE INDEX IF NOT EXISTS idx_imported ON extracted_text(imported);";
          
    rc = sqlite3_exec(*db, sql, 0, 0, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", errmsg);
        sqlite3_free(errmsg);
        sqlite3_close(*db);
        exit(EXIT_FAILURE);
    }
    sqlite3_free(errmsg);  // Free errmsg after successful execution
}

void close_db(sqlite3 *db) {
    if (db) {
        // Checkpoint the WAL file to write any remaining transactions to the main database
        int rc = sqlite3_wal_checkpoint(db, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to checkpoint WAL: %s\n", sqlite3_errmsg(db));
        }

        // Close the database connection
        rc = sqlite3_close(db);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Failed to close the database: %s\n", sqlite3_errmsg(db));
        } else {
            printf("Database closed successfully.\n");
        }
    }
}


int should_process_file(sqlite3 *db, const char *filename, int file_size_kb) {
    pthread_mutex_lock(&db_mutex);  // Acquire the mutex

    const char *sql = "SELECT COUNT(*) FROM extracted_text WHERE filename = ? AND file_size_kb = ?;";
    sqlite3_stmt *stmt;
    int result = 0;

    // Prepare the SQL statement
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        pthread_mutex_unlock(&db_mutex);  // Ensure the mutex is unlocked
        return 0;  // Return 0 to indicate that the file should not be processed
    }

    // Bind the parameters to the SQL query
    sqlite3_bind_text(stmt, 1, filename, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, file_size_kb);
    
    // Execute the query and check the result
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result = sqlite3_column_int(stmt, 0) == 0;  // If count is 0, process the file
    }

    // Finalize the statement to release resources
    sqlite3_finalize(stmt);

    pthread_mutex_unlock(&db_mutex);  // Release the mutex
    return result;
}

void preprocess_text(char *text) {
    // Log the original text (for debugging purposes)
    printf("Original text: \n%s\n", text);

    // Remove multiple spaces
    char *src = text, *dst = text;
    while (*src) {
        // Skip over multiple spaces
        while (isspace(*src) && isspace(*(src + 1))) {
            src++;
        }
        *dst++ = *src++;
    }
    *dst = '\0';

    // Log after removing extra spaces (for debugging purposes)
    printf("Text after removing extra spaces: \n%s\n", text);

    // Remove sensitive patterns using regex
    const char *patterns[] = {
        "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",  // Email
        "\\b[A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}\\b",             // IBAN
        "\\b[A-Z0-9]{8,11}\\b",                             // SWIFT Code
        "\\b[0-9]{10,15}\\b",                               // Phone numbers (generic)
        "\\b[A-Z]{6}[A-Z0-9]{2}[A-Z0-9]{7}\\b",             // Codice Fiscale (Italy)
        "\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b",                 // Social Security Number (USA)
        "\\b[0-9]{5,15}\\b"                                 // Insurance Numbers (generic)
    };

    regex_t regex;
    for (int i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
        if (regcomp(&regex, patterns[i], REG_EXTENDED) != 0) {
            // Log the error if the regex compilation fails
            fprintf(stderr, "Failed to compile regex pattern: %s\n", patterns[i]);
            continue;
        }

        regmatch_t match;
        while (regexec(&regex, text, 1, &match, 0) == 0) {
            // Replace the matched text with spaces
            memset(text + match.rm_so, ' ', match.rm_eo - match.rm_so);
        }
        regfree(&regex);
    }

    // Log the text after complete preprocessing (for debugging purposes)
    printf("Text after preprocessing: \n%s\n", text);
}


char* process_and_summarize_text(const char *preprocessed_text) {
    // Step 1: Select every fourth sentence
    char selected_text[5001] = "";
    char *selected_ptr = selected_text;  // Pointer to track the current position in selected_text
    int sentence_count = 0;
    const char *sentence_start = preprocessed_text;
    const char *sentence_end;
    
    while ((sentence_end = strstr(sentence_start, ".")) != NULL) {
        sentence_count++;
        if (sentence_count % 4 == 0) {
            size_t sentence_length = sentence_end - sentence_start + 1;
            
            // Check if the next sentence can fit into the buffer
            if ((selected_ptr - selected_text) + sentence_length >= 5000) {
                selected_text[5000] = '\0';
                break;
            }
            
            // Copy the sentence into selected_text
            strncpy(selected_ptr, sentence_start, sentence_length);
            selected_ptr += sentence_length;
            *selected_ptr = '\0';  // Null-terminate the string after each addition
        }
        sentence_start = sentence_end + 1;
    }

    // Step 2: Call OpenAI API to get a summary
    char *summary = call_openai_api(selected_text);
    if (summary == NULL) {
        fprintf(stderr, "Error getting summary from OpenAI for text: %s\n", selected_text);
        return NULL;
    }

    return summary;  // Return the summary
}


char *validate_utf8(const char *input) {
    iconv_t cd = iconv_open("UTF-8", "UTF-8");
    if (cd == (iconv_t)(-1)) {
        perror("iconv_open failed");
        return NULL;
    }

    size_t inbytesleft = strlen(input);
    size_t outbytesleft = inbytesleft * 2;  // Double the space for the output buffer
    char *output = malloc(outbytesleft);
    if (output == NULL) {
        perror("malloc failed for output buffer");
        iconv_close(cd);
        return NULL;
    }
    
    char *outbuf = output;
    char *inbuf = (char *)input;

    // Perform the conversion
    if (iconv(cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft) == (size_t)-1) {
        perror("iconv conversion failed");
        free(output);  // Free allocated memory in case of error
        iconv_close(cd);
        return NULL;
    }

    iconv_close(cd);
    *outbuf = '\0';  // Null-terminate the output string
    return output;   // The caller must free the returned memory
}


char* sanitize_and_validate_text(char *text) {
    sanitize_text(text);  // Sanitize the text by removing non-printable characters

    char *validated_text = validate_utf8(text);
    if (validated_text == NULL) {
        // If validation fails, return the original text.
        return text;
    }

    // If the validation succeeds, return the validated text.
    // The caller should free the returned text if it is different from the original.
    return validated_text;
}

void sanitize_text(char *text) {
    char *src = text, *dst = text;
    while (*src) {
        if (isprint((unsigned char)*src) || isspace((unsigned char)*src)) {
            *dst++ = *src;
        }
        src++;
    }
    *dst = '\0';  // Null-terminate the sanitized text
}


int save_to_db(sqlite3 *db, const char *filename, const char *text, const char *operation_time, const char *last_modified_time, int file_size_kb) {
    printf("Saving to database...\n");
    printf("Filename: %s\n", filename);
    printf("Text length: %lu\n", strlen(text));
    printf("Operation time: %s\n", operation_time);
    printf("Last modified time: %s\n", last_modified_time);
    printf("File size KB: %d\n", file_size_kb);

    // Duplicate text for modification
    char *modifiable_text = strdup(text);
    if (modifiable_text == NULL) {
        fprintf(stderr, "Failed to allocate memory for modifiable_text.\n");
        return -1;
    }

    // Sanitize the text
    sanitize_text(modifiable_text);
    char *validated_text = validate_utf8(modifiable_text);
    if (validated_text == NULL) {
        fprintf(stderr, "Validation failed, skipping save.\n");
        free(modifiable_text);
        return -1;
    }

    // Attempt to insert into database with retry mechanism
    int retries = 0;
    int rc;
    while (retries < MAX_RETRIES) {
        pthread_mutex_lock(&db_mutex);

        char *sql = "INSERT INTO extracted_text (filename, text, operation_time, last_modified_time, file_size_kb, imported, resume) VALUES (?, ?, ?, ?, ?, ?, ?);";
        sqlite3_stmt *stmt;

        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
            fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
            pthread_mutex_unlock(&db_mutex);
            free(validated_text);
            free(modifiable_text);
            return -1;
        }

        sqlite3_bind_text(stmt, 1, filename, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, validated_text, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, operation_time, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, last_modified_time, -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 5, file_size_kb);
        sqlite3_bind_int(stmt, 6, 0);  // Set 'imported' column to 0

        // Optional: Get summary using OpenAI
        char *summary = process_and_summarize_text(validated_text);
        if (summary != NULL) {
            printf("Inserting into DB: %s\n", summary);
            sqlite3_bind_text(stmt, 7, summary, -1, SQLITE_TRANSIENT);
            free(summary);
        } else {
            printf("Summary is NULL, inserting NULL into the database.\n");
            sqlite3_bind_null(stmt, 7);
        }

        rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) {
            printf("Database insertion successful.\n");
            sqlite3_finalize(stmt);
            pthread_mutex_unlock(&db_mutex);
            free(validated_text);  // Free memory for validated text
            free(modifiable_text); // Free memory for modifiable text
            return 0;
        } else {
            fprintf(stderr, "SQL error during insertion: %s\n", sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            pthread_mutex_unlock(&db_mutex);
            retries++;
            usleep(RETRY_DELAY);  // Delay before retry
        }
    }

    // Cleanup on failure
    free(validated_text);  // Ensure memory is freed
    free(modifiable_text); // Ensure memory is freed
    printf("Failed to save to database after %d retries\n", retries);
    return -1;
}


int is_blank_page(const char *text) {
    // Traverse through the string
    while (*text) {
        // Check if the current character is not a whitespace
        if (!isspace((unsigned char)*text)) {
            return 0;  // Found a non-whitespace character
        }
        text++;
    }
    return 1;  // All characters are whitespace or the string is empty
}



void parse_txt_file(const char *filepath) {
    FILE *file = fopen(filepath, "r");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    struct stat attr;
    stat(filepath, &attr);
    char last_modified_time[20];
    strftime(last_modified_time, sizeof(last_modified_time), "%Y-%m-%d %H:%M:%S", localtime(&(attr.st_mtime)));

    int file_size_kb = attr.st_size / 1024;

    if (!should_process_file(db, filepath, file_size_kb)) {
        log_message("DEBUG", "File already processed with same size, skipping.");
        fclose(file);
        return;
    }

    char buffer[1024];
    char *text = malloc(1);
    text[0] = '\0';
    size_t text_size = 1;

    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        text_size += strlen(buffer);
        text = realloc(text, text_size);
        strcat(text, buffer);
    }

    time_t now = time(NULL);
    char operation_time[20];
    strftime(operation_time, sizeof(operation_time), "%Y-%m-%d %H:%M:%S", localtime(&now));

    save_to_db(db, filepath, text, operation_time, last_modified_time, file_size_kb);

    free(text);
    fclose(file);
}

// Prototipo della funzione hash
unsigned long hash(const char *str);

void *process_file(void *arg) {
	pthread_mutex_lock(&file_mutex);
    thread_data_t *data = (thread_data_t *)arg;
    char *filepath = data->filepath;
	
	open_db(&db);

    if (strstr(filepath, ".txt")) {
        parse_txt_file(filepath);
    } else if (strstr(filepath, ".rtf")) {
        parse_rtf_file(filepath);
    } else if (strstr(filepath, ".pdf")) {
        parse_pdf_file(filepath);
    } else if (strstr(filepath, ".doc") || strstr(filepath, ".docx")) {
        parse_doc_file(filepath);
    }
	
	close_db(db);

    // Elimina il file dopo la lavorazione
    delete_file(filepath);
	pthread_mutex_unlock(&file_mutex);

    free(data);
    pthread_exit(NULL);
}

void parse_pdf_file(const char *filepath) {
    // Create a temporary directory for image files
    char temp_dir[1024];
    snprintf(temp_dir, sizeof(temp_dir), "%s/%lx", TEMP_IMAGE_DIR, hash(filepath));
    if (mkdir(temp_dir, 0777) != 0) {
        if (errno != EEXIST) {
            perror("Error creating temp directory");
            return;
        } else {
            printf("Directory already exists: %s\n", temp_dir);
        }
    } else {
        printf("Created directory: %s\n", temp_dir);
    }

    // Check if the PDF file exists
    if (access(filepath, F_OK) != 0) {
        fprintf(stderr, "File %s does not exist. Cannot process PDF.\n", filepath);
        return;
    }

    // Convert PDF to images
    char command[1024];
    // snprintf(command, sizeof(command), "pdftoppm '%s' %s/outputfile -png", filepath, temp_dir);
	snprintf(command, sizeof(command), "pdftoppm -png -r 96 '%s' '%s/outputfile'", filepath, temp_dir);
    int ret = system(command);
    if (ret != 0) {
        perror("Error executing pdftoppm");
        return;
    }

    // Allocate memory for extracted text
    char *text = malloc(1);
    if (text == NULL) {
        perror("Memory allocation failed");
        return;
    }
    text[0] = '\0';
    size_t text_size = 1;

    for (int i = 1; i <= 500; i++) {
        char image_file[1024];

        // Try format with three digits (outputfile-001.png)
        snprintf(image_file, sizeof(image_file), "%s/outputfile-%03d.png", temp_dir, i);

        // If the file doesn't exist, try format with two digits (outputfile-01.png)
        if (access(image_file, F_OK) == -1) {
            snprintf(image_file, sizeof(image_file), "%s/outputfile-%02d.png", temp_dir, i);
            if (access(image_file, F_OK) == -1) {
                printf("Image file %s does not exist, stopping.\n", image_file);
                break; // Stop if neither format exists
            }
        }

        printf("Processing image: %s\n", image_file);

        char ocr_output_file[1024];
        snprintf(ocr_output_file, sizeof(ocr_output_file), "%s/ocr_output-%d", temp_dir, i);
        snprintf(command, sizeof(command), "tesseract '%s' '%s'", image_file, ocr_output_file);
        ret = system(command);
        if (ret != 0) {
            printf("Error executing tesseract on %s: %s\n", image_file, strerror(errno));
            continue;
        }

        char ocr_output_txt_file[1024];
        snprintf(ocr_output_txt_file, sizeof(ocr_output_txt_file), "%s.txt", ocr_output_file);
        FILE *file = fopen(ocr_output_txt_file, "r");
        if (file == NULL) {
            perror("Error opening OCR output file");
            continue;
        }

        // Read OCR output and concatenate to text
        char buffer[1024];
        while (fgets(buffer, sizeof(buffer), file) != NULL) {
            size_t buffer_length = strlen(buffer);
            text_size += buffer_length;
            char *new_text = realloc(text, text_size);
            if (new_text == NULL) {
                perror("Memory reallocation failed");
                free(text);
                fclose(file);
                return;
            }
            text = new_text;
            strcat(text, buffer);
        }
        fclose(file);

        // Log the extracted text from each image
        // printf("Extracted text from image %d: %s\n", i, text);
    }

    // If no text was extracted, skip saving to the database
    if (strlen(text) == 0) {
        printf("No text extracted from %s, skipping database save.\n", filepath);
        free(text);
        return;
    }

    // Logging before saving to the database
	log_message("INFO", "Final extracted text size: %lu characters",  strlen(text));
    log_message("DEBUG", "Final extracted text: %s", text);

    // Get file attributes
    struct stat attr;
    if (stat(filepath, &attr) != 0) {
        perror("Error getting file attributes");
        free(text);
        // return;
    }
    char last_modified_time[20];
    strftime(last_modified_time, sizeof(last_modified_time), "%Y-%m-%d %H:%M:%S", localtime(&(attr.st_mtime)));

    int file_size_kb = attr.st_size / 1024;

    // Get current time for operation time
    time_t now = time(NULL);
    char operation_time[20];
    strftime(operation_time, sizeof(operation_time), "%Y-%m-%d %H:%M:%S", localtime(&now));

    // Save text to database
    int save_result = save_to_db(db, filepath, text, operation_time, last_modified_time, file_size_kb);
    if (save_result == 0) {
        log_message("INFO", "Text successfully saved to database for file %s.", filepath);
    } else {
		log_message("ERROR", "Failed to save text to database for file %s.", filepath);
    }

    // Free allocated memory
    free(text);

    // Clean up temporary directory
    char remove_command[1024];
    snprintf(remove_command, sizeof(remove_command), "rm -rf %s", temp_dir);
    system(remove_command);
}


// Funzione hash semplice per generare nomi di cartelle
unsigned long hash(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    return hash;
}


void parse_rtf_file(const char *filepath) {
    log_message("INFO", "Parsing RTF file...");

    // Comando per estrarre il testo da un file RTF usando unrtf
    char command[1024];
    snprintf(command, sizeof(command), "unrtf --text '%s'", filepath);

    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("Error executing unrtf");
        return;
    }

    char buffer[1024];
    char *text = malloc(1);
    text[0] = '\0';
    size_t text_size = 1;

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        text_size += strlen(buffer);
        text = realloc(text, text_size);
        strcat(text, buffer);
    }

    pclose(fp);

    struct stat attr;
    stat(filepath, &attr);
    char last_modified_time[20];
    strftime(last_modified_time, sizeof(last_modified_time), "%Y-%m-%d %H:%M:%S", localtime(&(attr.st_mtime)));

    int file_size_kb = attr.st_size / 1024;

    time_t now = time(NULL);
    char operation_time[20];
    strftime(operation_time, sizeof(operation_time), "%Y-%m-%d %H:%M:%S", localtime(&now));

    save_to_db(db, filepath, text, operation_time, last_modified_time, file_size_kb);

    free(text);
}


void parse_doc_file(const char *filepath) {
    log_message("INFO", "Parsing DOC/DOCX file...");

    char command[1024];
    char *text = NULL;
    size_t text_size = 1;

    // Estrai il nome del file senza percorso
    char *filename_base = strrchr(filepath, '/') + 1;

    // Costruisci il percorso completo per il file .txt generato
    char temp_txt_filepath[1024];
    snprintf(temp_txt_filepath, sizeof(temp_txt_filepath), "/tmp/%s", filename_base);
    char *dot = strrchr(temp_txt_filepath, '.');
    if (dot) {
        strcpy(dot, ".txt");  // Sostituisce l'estensione con .txt
    }

    // Verifica se l'estensione è valida (doc o docx)
    if (strstr(filepath, ".docx") == NULL && strstr(filepath, ".doc") == NULL) {
        log_message("DEBUG", "Unsupported file extension, skipping file.");
        return;
    }

    // Comando per convertire il file DOC o DOCX in testo
    snprintf(command, sizeof(command), "libreoffice --headless --convert-to txt:Text --outdir /tmp '%s' > /tmp/libreoffice_output.log 2>&1", filepath);
    int ret = system(command);  // Esegui il comando

    if (ret != 0) {
        perror("Error executing LibreOffice for DOCX conversion");
        return;
    }

    // Verifica che il file .txt sia stato creato
    if (access(temp_txt_filepath, F_OK) != 0) {
        printf("Text file %s not found after conversion. Conversion may have failed.\n", temp_txt_filepath);
        return;
    }

    FILE *fp = fopen(temp_txt_filepath, "r");
    if (fp == NULL) {
        perror("Error opening converted DOCX file");
        return;
    }

    text = malloc(1);
    text[0] = '\0';

    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        text_size += strlen(buffer);
        text = realloc(text, text_size);
        strcat(text, buffer);
    }

    fclose(fp);
    remove(temp_txt_filepath);  // Rimuovi il file temporaneo solo dopo averlo letto

    // Log del testo estratto per verifica
    printf("Extracted text from DOCX: %s\n", text);

    if (strlen(text) == 0) {
        printf("No text extracted from DOCX file %s, skipping database save.\n", filepath);
        free(text);
        return;
    }

    // Salva il testo nel database
    struct stat attr;
    stat(filepath, &attr);
    char last_modified_time[20];
    strftime(last_modified_time, sizeof(last_modified_time), "%Y-%m-%d %H:%M:%S", localtime(&(attr.st_mtime)));

    int file_size_kb = attr.st_size / 1024;

    time_t now = time(NULL);
    char operation_time[20];
    strftime(operation_time, sizeof(operation_time), "%Y-%m-%d %H:%M:%S", localtime(&now));

    int save_result = save_to_db(db, filepath, text, operation_time, last_modified_time, file_size_kb);
    if (save_result == 0) {
        log_message("INFO", "Text successfully saved to database.");
    } else {
        log_message("ERROR", "Failed to save text to database.");
    }

    free(text);  // Libera la memoria allocata per text
}

int is_temp_file(const char *filename) {
    return strstr(filename, ".part") != NULL;  // Check if the file is a temporary file (.part)
}

void log_message(const char *level, const char *message, ...) {
    // Get the current time
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    
    // Prepare the timestamp in the format [YYYY-MM-DD HH:MM:SS]
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    // Print the log level, timestamp, and message
    printf("[%s] [%s] ", level ? level : "INFO", timestamp);

    // Handle variable arguments for the log message
    va_list args;
    va_start(args, message);
    vprintf(message, args);
    va_end(args);

    // End the log line
    printf("\n");
}

void delete_file(const char *filepath) {
    log_message("DEBUG", "Attempting to delete file...");

    // Check if the file exists before attempting to delete it
    if (access(filepath, F_OK) == 0) {
        // File exists, attempt to delete it
        if (remove(filepath) == 0) {
            log_message("INFO", "File deleted successfully.");
        } else {
            // Log the specific error message
            log_message("ERROR", "Error deleting file.");
            log_message("ERROR", strerror(errno));  // Provides a textual description of the error
        }
    } else {
        // File does not exist
        log_message("WARNING", "File does not exist, no deletion needed.");
    }
}

// Checks if the file has a valid extension (doc, docx, txt, pdf, rtf)
int has_valid_extension(const char *filename) {
    const char *valid_extensions[] = {".doc", ".docx", ".txt", ".pdf", ".rtf"};
    int num_extensions = sizeof(valid_extensions) / sizeof(valid_extensions[0]);

    for (int i = 0; i < num_extensions; i++) {
        if (strstr(filename, valid_extensions[i]) != NULL) {
            return 1;  // Valid extension found
        }
    }
    return 0;  // No valid extension
}

typedef struct {
    char filepath[1024];
    bool processing;
} FileProcessing;

// Array per tenere traccia dei file in fase di elaborazione
FileProcessing file_processing_list[MAX_FILES];
int file_processing_count = 0;

bool is_file_processing(const char *filepath) {
    for (int i = 0; i < file_processing_count; i++) {
        if (strcmp(file_processing_list[i].filepath, filepath) == 0) {
            return file_processing_list[i].processing;
        }
    }
    return false;
}

void mark_file_processing(const char *filepath) {
    for (int i = 0; i < file_processing_count; i++) {
        if (strcmp(file_processing_list[i].filepath, filepath) == 0) {
            file_processing_list[i].processing = true;
            return;
        }
    }
    if (file_processing_count < MAX_FILES) {
        strcpy(file_processing_list[file_processing_count].filepath, filepath);
        file_processing_list[file_processing_count].processing = true;
        file_processing_count++;
    }
}

void mark_file_processed(const char *filepath) {
    for (int i = 0; i < file_processing_count; i++) {
        if (strcmp(file_processing_list[i].filepath, filepath) == 0) {
            file_processing_list[i].processing = false;
            return;
        }
    }
}

void remove_file_from_list(const char *filepath) {
    for (int i = 0; i < file_processing_count; i++) {
        if (strcmp(file_processing_list[i].filepath, filepath) == 0) {
            // Shift all subsequent elements to the left
            for (int j = i; j < file_processing_count - 1; j++) {
                file_processing_list[j] = file_processing_list[j + 1];
            }
            file_processing_count--;
            return;
        }
    }
}

int main() {

    // Environment variable checks and initialization...

    init_db(&db);
	close_db(db);

    int fd = inotify_init();
    if (fd < 0) {
        perror("inotify_init");
        exit(EXIT_FAILURE);
    }

    int wd = inotify_add_watch(fd, WATCH_PATH, IN_CREATE | IN_MOVED_TO | IN_CLOSE_WRITE);
    if (wd == -1) {
        perror("inotify_add_watch");
        exit(EXIT_FAILURE);
    }

    log_message("INFO", "Started watching directory.");
    printf("Watching directory: %s\n", WATCH_PATH);

    char buffer[EVENT_BUF_LEN];

    while (1) {
        int length = read(fd, buffer, EVENT_BUF_LEN);
        if (length < 0) {
            perror("read");
            exit(EXIT_FAILURE);
        }

        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            if (event->len) {
                char log_buffer[1024];
                char filepath[1024];

                snprintf(filepath, sizeof(filepath), "%s/%s", WATCH_PATH, event->name);
                printf("Detected file: %s\n", event->name);

                if (is_temp_file(event->name)) {
                    snprintf(log_buffer, sizeof(log_buffer), "Ignoring file: %s (temporary .part file)", event->name);
                    log_message("DEBUG", log_buffer);
                }
                else if (event->mask & IN_CREATE) {
                    snprintf(log_buffer, sizeof(log_buffer), "New file detected: %s", event->name);
                    log_message("INFO", log_buffer);
                }
                else if (event->mask & IN_MOVED_TO) {
                    snprintf(log_buffer, sizeof(log_buffer), "File renamed or moved to: %s", event->name);
                    log_message("DEBUG", log_buffer);

                    if (access(filepath, F_OK) != -1) {
                        if (!is_file_processing(filepath)) {
                            mark_file_processing(filepath);
                            snprintf(log_buffer, sizeof(log_buffer), "Processing file: %s", event->name);
                            log_message("INFO", log_buffer);
                            start_thread_for_file(filepath);
                        } else {
                            snprintf(log_buffer, sizeof(log_buffer), "File %s is already being processed.", event->name);
                            log_message("INFO", log_buffer);
                        }
                    } else {
                        snprintf(log_buffer, sizeof(log_buffer), "File %s not found or inaccessible.", event->name);
                        log_message("WARNING", log_buffer);
                    }
                }
                else if (event->mask & IN_CLOSE_WRITE) {
                    snprintf(log_buffer, sizeof(log_buffer), "File closed after writing: %s", event->name);
                    log_message("DEBUG", log_buffer);

                    if (is_temp_file(event->name)) {
                        snprintf(log_buffer, sizeof(log_buffer), "Ignoring .part file after close: %s", event->name);
                        log_message("DEBUG", log_buffer);
                    }
                    else if (access(filepath, F_OK) != -1 && has_valid_extension(event->name)) {
                        snprintf(log_buffer, sizeof(log_buffer), "File %s is complete. Processing...", event->name);
                        log_message("INFO", log_buffer);

                        if (!is_file_processing(filepath)) {
                            mark_file_processing(filepath);
                            start_thread_for_file(filepath);
                        }
                    } else {
                        snprintf(log_buffer, sizeof(log_buffer), "File %s does not have a valid extension or was not found. Ignoring...", event->name);
                        log_message("WARNING", log_buffer);
                    }

                    // After processing is complete, remove file from the list
                    mark_file_processed(filepath);
                    remove_file_from_list(filepath);
                }
            }
            i += sizeof(struct inotify_event) + event->len;
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);

    return 0;
}