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

#define DEFAULT_OPENAI_API_KEY ""
#define DEFAULT_WATCH_PATH ""
#define DEFAULT_TEMP_IMAGE_DIR "/tmp/pdf_images"

#define OPENAI_API_KEY (getenv("OPENAI_API_KEY") ? getenv("OPENAI_API_KEY") : DEFAULT_OPENAI_API_KEY)
#define WATCH_PATH (getenv("WATCH_PATH") ? getenv("WATCH_PATH") : DEFAULT_WATCH_PATH)
#define TEMP_IMAGE_DIR (getenv("WATCH_PATH") ? getenv("WATCH_PATH") : DEFAULT_TEMP_IMAGE_DIR)


#define MAX_TEXT_LENGTH 3500
#define EVENT_BUF_LEN (1024 * (sizeof(struct inotify_event) + 16))
#define MAX_RETRIES 5
#define RETRY_DELAY 100000  // 100 ms

// Mutex per la sincronizzazione dell'accesso al database
pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;
sqlite3 *db = NULL;  // Connessione globale al database

// Function prototypes
void parse_txt_file(const char *filepath);
void parse_rtf_file(const char *filepath);
void parse_pdf_file(const char *filepath);
void parse_doc_file(const char *filepath);
int has_valid_extension(const char *filename);
void delete_file(const char *filepath);
void log_message(const char *message);
void init_db(sqlite3 **db);
int should_process_file(sqlite3 *db, const char *filename, int file_size_kb);
int save_to_db(sqlite3 *db, const char *filename, const char *text, const char *operation_time, const char *last_modified_time, int file_size_kb);
void sanitize_text(char *text);  // Aggiunta della dichiarazione
char* sanitize_and_validate_text(char *text);
char* call_openai_api(const char *text);

typedef struct {
    char filepath[1024];
} thread_data_t;

void *process_file(void *arg);

struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(ptr == NULL) {
        printf("not enough memory (realloc returned NULL)\n");
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

    char *summary = strdup(content->valuestring);
    cJSON_Delete(json);
    return summary;
}

char* escape_json_string(const char *input) {
    size_t length = strlen(input);
    size_t escaped_length = length * 2 + 1; // Allocate enough space
    char *escaped = malloc(escaped_length);
    if (!escaped) return NULL;

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
    *q = '\0';
    printf("Escaped string: %s\n", escaped);
    return escaped;
}

char* call_openai_api(const char *text) {
    CURL *curl;
    CURLcode res;

    struct MemoryStruct chunk;
    chunk.memory = malloc(1);
    chunk.size = 0;

    char truncated_text[MAX_TEXT_LENGTH + 1];
    strncpy(truncated_text, text, MAX_TEXT_LENGTH);
    truncated_text[MAX_TEXT_LENGTH] = '\0';

    char *escaped_text = escape_json_string(truncated_text);
    if (!escaped_text) {
        fprintf(stderr, "Failed to escape JSON string\n");
        return NULL;
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.openai.com/v1/chat/completions");

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        // Costruisci l'header Authorization con la chiave API
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
            free(chunk.memory);
            chunk.memory = NULL;
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }

    curl_global_cleanup();
    free(escaped_text);

    if (chunk.memory) {
        char *summary = escape_json_string(parse_openai_response(chunk.memory));
        free(chunk.memory);  // Libera la memoria dell'intera risposta JSON
        return summary;      // Restituisce solo il riassunto estratto
    }

    return NULL;
}


void start_thread_for_file(const char *filepath) {
    pthread_t thread;
    thread_data_t *data = malloc(sizeof(thread_data_t));
    strcpy(data->filepath, filepath);
    pthread_create(&thread, NULL, process_file, data);
    pthread_detach(thread);
}

int trace_callback(unsigned int trace_type, void *ctx, void *p, void *x) {
    const char *sql = (const char *)x;
    printf("Executing SQL: %s\n", sql);
    return 0;  // Restituisce 0 per indicare che la traccia è stata gestita correttamente
}

void init_db(sqlite3 **db) {
    int rc = sqlite3_open("text_extractor.db", db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(*db));
        exit(EXIT_FAILURE);
    }

    sqlite3_trace_v2(*db, SQLITE_TRACE_STMT, trace_callback, NULL);

    // Forza l'encoding UTF-8
    char *errmsg = 0;
    rc = sqlite3_exec(*db, "PRAGMA encoding = 'UTF-8';", 0, 0, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to set UTF-8 encoding: %s\n", errmsg);
        sqlite3_free(errmsg);
        sqlite3_close(*db);
        exit(EXIT_FAILURE);
    }

    // Abilita WAL mode per migliorare la concorrenza
    sqlite3_exec(*db, "PRAGMA journal_mode=WAL;", 0, 0, 0);

    // Creazione della tabella con le nuove colonne 'imported' e 'resume'
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
        sqlite3_free(errmsg);
        sqlite3_close(*db);
        exit(EXIT_FAILURE);
    }

    // Creazione degli indici per migliorare le prestazioni
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
}


int should_process_file(sqlite3 *db, const char *filename, int file_size_kb) {
    pthread_mutex_lock(&db_mutex);  // Acquisisci il mutex

    char *sql = "SELECT COUNT(*) FROM extracted_text WHERE filename = ? AND file_size_kb = ?;";
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, filename, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, file_size_kb);
    
    int result = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result = sqlite3_column_int(stmt, 0) == 0;
    }
    sqlite3_finalize(stmt);

    pthread_mutex_unlock(&db_mutex);  // Rilascia il mutex
    return result;
}


void preprocess_text(char *text) {
    // Log del testo originale
    printf("Original text: \n%s\n", text);

    // Rimozione degli spazi bianchi multipli
    char *src = text, *dst = text;
    while (*src) {
        // Rimuovi spazi bianchi multipli
        while (isspace(*src) && isspace(*(src + 1))) {
            src++;
        }
        *dst++ = *src++;
    }
    *dst = '\0';

    // Log dopo la rimozione degli spazi bianchi multipli
    printf("Text after removing extra spaces: \n%s\n", text);

    // Rimuovi pattern sensibili tramite regex
    const char *patterns[] = {
        "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",  // Email
        "\\b[A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}\\b",             // IBAN
        "\\b[A-Z0-9]{8,11}\\b",                             // SWIFT Code
        "\\b[0-9]{10,15}\\b",                               // Numeri di telefono (generic)
        "\\b[A-Z]{6}[A-Z0-9]{2}[A-Z0-9]{7}\\b",             // Codice Fiscale (Italia)
        "\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b",                 // Social Security Number (USA)
        "\\b[0-9]{5,15}\\b"                                 // Insurance Numbers (generic)
    };

    regex_t regex;
    for (int i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
        if (regcomp(&regex, patterns[i], REG_EXTENDED) != 0) {
            continue;  // Se la regex non può essere compilata, passa al prossimo pattern
        }

        regmatch_t match;
        while (regexec(&regex, text, 1, &match, 0) == 0) {
            // Sostituisci il match con spazi vuoti
            memset(text + match.rm_so, ' ', match.rm_eo - match.rm_so);
        }
        regfree(&regex);
    }

    // Log del testo dopo il preprocessamento completo
    printf("Text after preprocessing: \n%s\n", text);
}

char* process_and_summarize_text(const char *preprocessed_text) {
    // Step 1: Seleziona una frase ogni 3
    char selected_text[5001] = "";
    int sentence_count = 0;
    char *sentence_start = (char *)preprocessed_text;
    char *sentence_end;
    
    while ((sentence_end = strstr(sentence_start, ".")) != NULL) {
        sentence_count++;
        if (sentence_count % 4 == 0) {
            strncat(selected_text, sentence_start, sentence_end - sentence_start + 1);
            if (strlen(selected_text) >= 5000) {
                selected_text[5000] = '\0';
                break;
            }
        }
        sentence_start = sentence_end + 1;
    }

    // Step 2: Chiamata a OpenAI per ottenere un riassunto
    char *summary = call_openai_api(selected_text);
    if (summary == NULL) {
        fprintf(stderr, "Error getting summary from OpenAI\n");
        return NULL;
    }

    return summary;  // Restituisce il riassunto
}

char *validate_utf8(const char *input) {
    iconv_t cd = iconv_open("UTF-8", "UTF-8");
    if (cd == (iconv_t)(-1)) {
        perror("iconv_open failed");
        return NULL;
    }

    size_t inbytesleft = strlen(input);
    size_t outbytesleft = inbytesleft * 2;
    char *output = malloc(outbytesleft);
    char *outbuf = output;

    char *inbuf = (char *)input;

    if (iconv(cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft) == (size_t)-1) {
        perror("iconv failed");
        free(output);
        iconv_close(cd);
        return NULL;
    }

    iconv_close(cd);
    *outbuf = '\0';
    return output;
}

char* sanitize_and_validate_text(char *text) {
    sanitize_text(text);
    char *validated_text = validate_utf8(text);
    if (validated_text == NULL) {
        return text;  // Se la validazione fallisce, ritorna il testo originale.
    }
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
    *dst = '\0';
}

int save_to_db(sqlite3 *db, const char *filename, const char *text, const char *operation_time, const char *last_modified_time, int file_size_kb) {
    printf("Saving to database...\n");
    printf("Filename: %s\n", filename);
    printf("Text length: %lu\n", strlen(text));
    printf("Operation time: %s\n", operation_time);
    printf("Last modified time: %s\n", last_modified_time);
    printf("File size KB: %d\n", file_size_kb);

    // Duplica il testo per renderlo modificabile
    char *modifiable_text = strdup(text);
    if (modifiable_text == NULL) {
        fprintf(stderr, "Failed to allocate memory for modifiable_text.\n");
        return -1;
    }

    // Sanificazione del testo
    sanitize_text(modifiable_text);   // Rimuove solo i caratteri di escape e non stampabili
    char *validated_text = validate_utf8(modifiable_text);
    if (validated_text == NULL) {
        fprintf(stderr, "Validation failed, skipping save.\n");
        free(modifiable_text);
        return -1;
    }
    // Inserisci il testo nel database
    int retries = 0;
    int rc;

    while (retries < MAX_RETRIES) {
        pthread_mutex_lock(&db_mutex);

        char *sql = "INSERT INTO extracted_text (filename, text, operation_time, last_modified_time, file_size_kb, imported, resume) VALUES (?, ?, ?, ?, ?, ?, ?);";
        sqlite3_stmt *stmt;

        sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
        sqlite3_bind_text(stmt, 1, filename, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, validated_text, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, operation_time, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, last_modified_time, -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 5, file_size_kb);
        sqlite3_bind_int(stmt, 6, 0);  // Valorizza la colonna imported con 0

        // Riassunto usando OpenAI (opzionale)
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
            free(validated_text);  // Libera la memoria del testo validato
            free(modifiable_text); // Libera la memoria del testo modificabile
            return 0;
        } else {
            fprintf(stderr, "SQL error during insertion: %s\n", sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            pthread_mutex_unlock(&db_mutex);
            retries++;
            usleep(RETRY_DELAY);
        }
    }

    free(validated_text);  // Assicurati di liberare anche in caso di errore
    free(modifiable_text); // Assicurati di liberare anche in caso di errore
    printf("Failed to save to database after %d retries\n", retries);
    return -1;
}




int is_blank_page(const char *text) {
    for (int i = 0; text[i] != '\0'; i++) {
        if (!isspace(text[i])) {
            return 0;
        }
    }
    return 1;
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
        log_message("File already processed with same size, skipping.");
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
    thread_data_t *data = (thread_data_t *)arg;
    char *filepath = data->filepath;

    if (strstr(filepath, ".txt")) {
        parse_txt_file(filepath);
    } else if (strstr(filepath, ".rtf")) {
        parse_rtf_file(filepath);
    } else if (strstr(filepath, ".pdf")) {
        parse_pdf_file(filepath);
    } else if (strstr(filepath, ".doc") || strstr(filepath, ".docx")) {
        parse_doc_file(filepath);
    }

    // Elimina il file dopo la lavorazione
    delete_file(filepath);

    free(data);
    pthread_exit(NULL);
}

void parse_pdf_file(const char *filepath) {
    char temp_dir[1024];
    snprintf(temp_dir, sizeof(temp_dir), "%s/%lx", TEMP_IMAGE_DIR, hash(filepath));
    // mkdir(temp_dir, 0777);
    if (mkdir(temp_dir, 0777) != 0) {
        perror("Error creating temp directory");
    return;
    } else {
        printf("Created directory: %s\n", temp_dir);
    }

    char command[1024];
    snprintf(command, sizeof(command), "pdftoppm '%s' %s/outputfile -png", filepath, temp_dir);
    int ret = system(command);
    if (ret != 0) {
        perror("Error executing pdftoppm");
        return;
    }

    char *text = malloc(1);
    text[0] = '\0';
    size_t text_size = 1;

    for (int i = 1; i <= 100; i++) {
        char image_file[1024];
        snprintf(image_file, sizeof(image_file), "%s/outputfile-%d.png", temp_dir, i);

        if (access(image_file, F_OK) == -1) {
            printf("Image file %s does not exist, stopping.\n", image_file);
            break;
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

        char buffer[1024];
        while (fgets(buffer, sizeof(buffer), file) != NULL) {
            size_t buffer_length = strlen(buffer);
            text_size += buffer_length;
            text = realloc(text, text_size);
            strcat(text, buffer);
        }

        fclose(file);

        // Log del testo estratto da ogni immagine
        printf("Extracted text from image %d: %s\n", i, text);
    }

    if (strlen(text) == 0) {
        printf("No text extracted from %s, skipping database save.\n", filepath);
        free(text);
        return;
    }

    // Logging prima di salvare nel database
    printf("Final extracted text size: %lu characters\n", strlen(text));
    printf("Final extracted text: %s\n", text);

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
        printf("Text successfully saved to database for file %s.\n", filepath);
    } else {
        printf("Failed to save text to database for file %s.\n", filepath);
    }

    free(text);

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
    log_message("Parsing RTF file...");

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
    log_message("Parsing DOC/DOCX file...");

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
        log_message("Unsupported file extension, skipping file.");
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
        log_message("Text successfully saved to database.");
    } else {
        log_message("Failed to save text to database.");
    }

    free(text);  // Libera la memoria allocata per text
}



int has_valid_extension(const char *filename) {
    return strstr(filename, ".txt") || strstr(filename, ".rtf") || 
           strstr(filename, ".pdf") || strstr(filename, ".doc") || 
           strstr(filename, ".docx");
}

void log_message(const char *message) {
    printf("%s\n", message);
}

void delete_file(const char *filepath) {
    log_message("Deleting file...");
    if (remove(filepath) == 0) {
        log_message("File deleted successfully.");
    } else {
        log_message("Error deleting file.");
    }
}

int main() {

    if (OPENAI_API_KEY != NULL && WATCH_PATH != NULL && TEMP_IMAGE_DIR != NULL) {
        printf("OPENAI_API_KEY: %s\n", OPENAI_API_KEY);
        printf("WATCH_PATH: %s\n", WATCH_PATH);
        printf("TEMP_IMAGE_DIR: %s\n", TEMP_IMAGE_DIR);
    } else {
        printf("Errore: variabili d'ambiente non trovate.\n");
        return 0;
    }

    init_db(&db);  // Inizializza la connessione al database globale

    int fd = inotify_init();
    if (fd < 0) {
        perror("inotify_init");
        exit(EXIT_FAILURE);
    }

    int wd = inotify_add_watch(fd, WATCH_PATH, IN_CREATE);
    if (wd == -1) {
        perror("inotify_add_watch");
        exit(EXIT_FAILURE);
    }

    log_message("Started watching directory.");
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
                if (event->mask & IN_CREATE) {
                    char log_buffer[1024];
                    snprintf(log_buffer, sizeof(log_buffer), "New file detected: %s", event->name);
                    log_message(log_buffer);

                    char filepath[1024];
                    snprintf(filepath, sizeof(filepath), "%s/%s", WATCH_PATH, event->name);

                    if (has_valid_extension(event->name)) {
                        snprintf(log_buffer, sizeof(log_buffer), "File %s has a valid extension. Processing...", event->name);
                        log_message(log_buffer);

                        start_thread_for_file(filepath);

                    } else {
                        snprintf(log_buffer, sizeof(log_buffer), "File %s does not have a valid extension. Ignoring...", event->name);
                        log_message(log_buffer);
                    }
                }
            }
            i += sizeof(struct inotify_event) + event->len;
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);
    sqlite3_close(db);  // Chiudi la connessione al database globale

    return 0;
}
